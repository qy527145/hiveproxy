//! L2 编解码：从异步流中读出一整帧 / 写出一整帧（DESIGN.md §7）。
//!
//! 帧在内存里始终是**一整块** `BytesMut`：头部 48 字节 + 载荷连续存放。
//! 中继只需改 `raw[3]`（ttl）这 1 个字节（§5.6）。

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::header::{HiveHeader, HEADER_LEN, MAGIC, MAX_FRAME_PAYLOAD, VERSION};
use crate::error::ProtoError;

/// 一整帧：解析出的头 + 含头的原始缓冲。
#[derive(Clone, Debug)]
pub struct RawFrame {
    pub header: HiveHeader,
    /// 头部 48 字节 + 载荷，连续存放。中继路径上改 `raw[3]` 即可。
    pub raw: BytesMut,
}

impl RawFrame {
    /// 组装一帧并校验载荷上限。
    pub fn build(mut header: HiveHeader, payload: &[u8]) -> Result<Self, ProtoError> {
        if payload.len() as u64 > MAX_FRAME_PAYLOAD as u64 {
            return Err(ProtoError::PayloadTooLarge(payload.len() as u32));
        }
        header.payload_len = payload.len() as u32;
        let mut raw = BytesMut::with_capacity(HEADER_LEN + payload.len());
        header.encode_into(&mut raw);
        raw.extend_from_slice(payload);
        Ok(Self { header, raw })
    }

    pub fn payload(&self) -> &[u8] {
        &self.raw[HEADER_LEN..]
    }

    /// 只改 1 字节的 TTL 递减（§5.6）。
    pub fn decrement_ttl(&mut self) -> u8 {
        let t = self.header.ttl.saturating_sub(1);
        self.header.ttl = t;
        self.raw[3] = t;
        t
    }

    /// 拆出载荷而不拷贝（`split_off` 只移动指针）。
    pub fn into_payload(self) -> (HiveHeader, Bytes) {
        let Self { header, mut raw } = self;
        let payload = raw.split_off(HEADER_LEN).freeze();
        (header, payload)
    }

    /// 拆出「头 + 载荷」的整块缓冲，用于零拷贝投递给下一跳。
    pub fn into_raw(self) -> (HiveHeader, Bytes) {
        let Self { header, raw } = self;
        (header, raw.freeze())
    }
}

/// 从异步流中读出一整帧。
///
/// 返回 `Ok(None)` 表示**对端在帧边界上正常关闭**；`Err(Truncated)` 表示读到一半就断了
/// —— 前者触发链路拆除 + 拓扑更新，后者立即拆链并记录（§7）。
///
/// **前 2 字节立刻校验 magic + version**：拨到非 hiveproxy 服务（HTTP/SSH/数据库…）时
/// 必须是一个廉价且确定性的失败，而不是"等满 48 字节 / 等超时"（§6.2.2、§6.2.3）。
///
/// ⚠️ 真实坑：HTTP 响应的首字节 `'H'` = `0x48` **恰好等于 magic**，
/// 所以真正拦住 HTTP 的是第 2 字节的版本位（`'T'` = `0x54` → version 5 ≠ 1）。
/// 只看首字节是不够的。
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<RawFrame>, ProtoError> {
    let mut head = [0u8; HEADER_LEN];
    let mut filled = 0usize;

    while filled < 2 {
        let n = r.read(&mut head[filled..2]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None); // 帧边界上的干净关闭
            }
            return Err(ProtoError::Truncated { need: HEADER_LEN, got: filled });
        }
        filled += n;
    }
    if head[0] != MAGIC {
        return Err(ProtoError::BadMagic(head[0]));
    }
    let version = head[1] >> 4;
    if version != VERSION {
        return Err(ProtoError::BadVersion(version));
    }

    while filled < HEADER_LEN {
        let n = r.read(&mut head[filled..]).await?;
        if n == 0 {
            return Err(ProtoError::Truncated { need: HEADER_LEN, got: filled });
        }
        filled += n;
    }

    let header = HiveHeader::decode(&head)?;
    let plen = header.payload_len as usize;

    let mut raw = BytesMut::with_capacity(HEADER_LEN + plen);
    raw.extend_from_slice(&head);

    if plen > 0 {
        raw.resize(HEADER_LEN + plen, 0);
        let mut got = 0usize;
        while got < plen {
            let n = r.read(&mut raw[HEADER_LEN + got..]).await?;
            if n == 0 {
                return Err(ProtoError::Truncated { need: HEADER_LEN + plen, got: HEADER_LEN + got });
            }
            got += n;
        }
    }

    Ok(Some(RawFrame { header, raw }))
}

/// 把一整帧写出去。relay 路径传入的就是从上游读到的同一块缓冲（ttl 已改）。
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, raw: &[u8]) -> Result<(), ProtoError> {
    w.write_all(raw).await?;
    Ok(())
}

/// 便捷写法：组装并写出一帧。
pub async fn write_msg<W, T>(w: &mut W, header: HiveHeader, msg: &T) -> Result<(), ProtoError>
where
    W: AsyncWrite + Unpin,
    T: serde::Serialize,
{
    let payload = super::encode_payload(msg)?;
    let frame = RawFrame::build(header, &payload)?;
    write_frame(w, &frame.raw).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{MsgType, NodeId};

    fn hdr(ty: MsgType, ttl: u8) -> HiveHeader {
        HiveHeader::new(
            ty,
            NodeId::from_ip("10.1.2.3".parse().unwrap()),
            NodeId::from_ip("10.4.0.9".parse().unwrap()),
            ttl,
        )
        .with_stream(7)
    }

    #[tokio::test]
    async fn roundtrip_single_frame() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frame = RawFrame::build(hdr(MsgType::Data, 8), b"hello hive").unwrap();
        tokio::spawn(async move {
            write_frame(&mut a, &frame.raw).await.unwrap();
        });
        let got = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got.header.msg_type, MsgType::Data);
        assert_eq!(got.header.stream_id, 7);
        assert_eq!(got.payload(), b"hello hive");
    }

    #[tokio::test]
    async fn roundtrip_zero_length_payload() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frame = RawFrame::build(hdr(MsgType::Ping, 1), b"").unwrap();
        tokio::spawn(async move {
            write_frame(&mut a, &frame.raw).await.unwrap();
        });
        let got = read_frame(&mut b).await.unwrap().unwrap();
        assert_eq!(got.payload().len(), 0);
    }

    #[tokio::test]
    async fn multiple_frames_in_one_stream() {
        let (mut a, mut b) = tokio::io::duplex(8192);
        let f1 = RawFrame::build(hdr(MsgType::Data, 8), b"first").unwrap();
        let f2 = RawFrame::build(hdr(MsgType::Data, 8), b"second").unwrap();
        tokio::spawn(async move {
            write_frame(&mut a, &f1.raw).await.unwrap();
            write_frame(&mut a, &f2.raw).await.unwrap();
        });
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap().payload(), b"first");
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap().payload(), b"second");
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none(), "帧边界上的关闭应当返回 None");
    }

    #[tokio::test]
    async fn truncated_header_is_a_protocol_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&[0x48, 0x1A, 0x00]).await.unwrap(); // 只有 3 字节
            a.shutdown().await.unwrap();
        });
        match read_frame(&mut b).await {
            Err(ProtoError::Truncated { need: HEADER_LEN, got: 3 }) => {}
            other => panic!("应当报 Truncated{{need:48, got:3}}，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_payload_is_a_protocol_error() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let frame = RawFrame::build(hdr(MsgType::Data, 8), b"0123456789").unwrap();
        let mut bytes = frame.raw.to_vec();
        bytes.truncate(bytes.len() - 4); // 砍掉载荷尾部
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(&bytes).await.unwrap();
            a.shutdown().await.unwrap();
        });
        assert!(matches!(read_frame(&mut b).await, Err(ProtoError::Truncated { .. })));
    }

    #[tokio::test]
    async fn non_hiveproxy_service_is_a_deterministic_failure() {
        // §6.2.2：拨到一个 HTTP 服务时必须**立刻**确定性失败。
        //
        // 注意这里的细节：HTTP 的首字节 'H' == MAGIC，所以拦下它的是第 2 字节的版本位。
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await.unwrap();
            // 故意不断开、也不继续发：如果实现要等满 48 字节，这里就会挂住
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut b))
            .await
            .expect("必须在拿到前 2 字节后立刻判定，而不是等超时");
        match res {
            Err(ProtoError::BadVersion(5)) => {} // 'T' = 0x54 → version 5
            other => panic!("应当报 BadVersion(5)，实际 {other:?}"),
        }
    }

    #[tokio::test]
    async fn non_hiveproxy_with_other_first_byte_fails_on_magic() {
        // SSH 服务首字节是 "SSH-2.0-..." 的 'S'，这里走 magic 分支。
        let (mut a, mut b) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        });
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut b))
            .await
            .expect("必须立刻判定");
        assert!(matches!(res, Err(ProtoError::BadMagic(b'S'))));
    }

    #[test]
    fn ttl_decrement_touches_exactly_one_byte() {
        let mut frame = RawFrame::build(hdr(MsgType::Data, 5), b"payload").unwrap();
        let before = frame.raw.to_vec();
        frame.decrement_ttl();
        let after = frame.raw.to_vec();
        assert_eq!(after[3], 4);
        let diff: Vec<usize> =
            (0..before.len()).filter(|&i| before[i] != after[i]).collect();
        assert_eq!(diff, vec![3], "中继只允许改 ttl 这 1 个字节（§5.6）");
    }

    #[test]
    fn oversize_payload_rejected_on_build() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD as usize + 1];
        assert!(matches!(
            RawFrame::build(hdr(MsgType::Data, 8), &big),
            Err(ProtoError::PayloadTooLarge(_))
        ));
    }

    #[test]
    fn into_payload_does_not_copy_header_over_payload() {
        let frame = RawFrame::build(hdr(MsgType::Data, 8), b"abc").unwrap();
        let (h, p) = frame.into_payload();
        assert_eq!(h.payload_len, 3);
        assert_eq!(&p[..], b"abc");
    }
}
