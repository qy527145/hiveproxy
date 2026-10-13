// 对象数组的小型行编辑器：`peers.entry`（别名表）与 `route.groups`（候选集）。
//
// 为什么值得单独做而不丢给下面的 TOML 文本框：
// - `peers.entry` 是 `egress = "alias:gpu-01"` 的解析依据，写错了规则会**静默**
//   变成"别名找不到"；在表单里成对填写不容易漏。
// - `route.groups` 是 `egress = "group:db"` 的成员来源。
// 两者都是"一多就容易抄错"的东西，表格比 TOML 更不容易出错。

export interface ListFieldSpec {
  key: string;
  label: string;
  placeholder?: string;
  /** 该字段在 Rust 侧是 `Vec<String>`：用逗号分隔填写。 */
  list?: boolean;
}

function cellText(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  if (value == null) return "";
  return String(value);
}

function parseCell(spec: ListFieldSpec, raw: string): unknown {
  if (!spec.list) return raw.trim();
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function ListEditor<T extends object>({
  title,
  rows,
  fields,
  empty,
  addRow,
  onChange,
}: {
  title: string;
  rows: T[];
  fields: ListFieldSpec[];
  empty: string;
  addRow: () => T;
  onChange: (rows: T[]) => void;
}) {
  const edit = (rowIndex: number, spec: ListFieldSpec, raw: string) => {
    onChange(
      rows.map((row, i) =>
        i === rowIndex
          ? ({ ...row, [spec.key]: parseCell(spec, raw) } as unknown as T)
          : row,
      ),
    );
  };

  return (
    <div className="listeditor">
      <div className="row between">
        <span className="sub">{title}</span>
        <button className="mini ghost" onClick={() => onChange([...rows, addRow()])}>
          + 新增一行
        </button>
      </div>
      {rows.length === 0 ? (
        <div className="empty">{empty}</div>
      ) : (
        <div className="tablewrap">
          <table>
            <thead>
              <tr>
                {fields.map((f) => (
                  <th key={f.key}>{f.label}</th>
                ))}
                <th style={{ width: 70 }} />
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                // 行本身就是数据，没有稳定 id；用下标当 key 对"行内编辑"是安全的
                // （增删都整表重建，不会出现错位复用）。
                <tr key={i}>
                  {fields.map((f) => {
                    const value = cellText((row as Record<string, unknown>)[f.key]);
                    return (
                      <td key={f.key}>
                        <input
                          value={value}
                          placeholder={f.placeholder}
                          onChange={(e) => edit(i, f, e.target.value)}
                        />
                      </td>
                    );
                  })}
                  <td>
                    <button
                      className="mini danger"
                      title="删除这一行"
                      onClick={() => onChange(rows.filter((_, j) => j !== i))}
                    >
                      ✕
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
