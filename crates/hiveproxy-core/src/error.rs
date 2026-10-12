//! 统一错误类型。

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("魔数不符: 期望 0x48, 实际 0x{0:02x}（该端口不是 hiveproxy 节点）")]
    BadMagic(u8),
    #[error("协议版本不支持: {0}")]
    BadVersion(u8),
    #[error("未知消息类型: 0x{0:x}")]
    UnknownMsgType(u8),
    #[error("载荷超限: {0} > {}", crate::proto::MAX_FRAME_PAYLOAD)]
    PayloadTooLarge(u32),
    #[error("帧被截断: 需要 {need} 字节, 只有 {got}")]
    Truncated { need: usize, got: usize },
    #[error("控制消息编解码失败: {0}")]
    Codec(String),
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("无路由到 {0}")]
    NoRoute(crate::proto::NodeId),
    #[error("下一跳不可用: {0}")]
    NextHopUnavailable(crate::proto::NodeId),
    #[error("TTL 耗尽")]
    TtlExhausted,
    #[error(transparent)]
    Proto(#[from] ProtoError),
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("解析失败: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("序列化失败: {0}")]
    Serialize(#[from] toml::ser::Error),
    #[error("I/O 错误: {0}")]
    Io(#[from] std::io::Error),
}
