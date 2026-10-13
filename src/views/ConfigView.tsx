import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { CONFIG_SECTIONS, getPath, setPath, type ConfigField } from "../lib/configSpec";
import type { Config } from "../lib/types";
import { ListEditor } from "../components/ListEditor";
import { Panel, Row } from "../components/ui";
import {
  configFromToml,
  configToToml,
  loadConfig,
  saveConfig,
  toast,
  validateConfig,
} from "../state/hive";
import { useConfig, useService } from "../state/useHive";

/** Config 是纯 JSON（没有 Date / Map），JSON 往返就是最省事的深拷贝。 */
function clone(cfg: Config): Config {
  return JSON.parse(JSON.stringify(cfg)) as Config;
}

function splitNums(s: string): number[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .map(Number);
}

function splitStrs(s: string): string[] {
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

export function ConfigView() {
  const config = useConfig();
  const svc = useService();

  const [draft, setDraft] = useState<Config | null>(null);
  const [dirty, setDirty] = useState(false);
  const [toml, setToml] = useState("");
  const [tomlOut, setTomlOut] = useState("（还没从磁盘读过配置 —— 点「从当前配置刷新」）");

  // 服务在跑时配置会被引擎热更新，所以外部值一变就跟上 —— 但**绝不动**你正在改的草稿。
  useEffect(() => {
    if (!config || dirty) return;
    setDraft(clone(config));
  }, [config, dirty]);

  function patch(path: string, value: unknown) {
    setDraft((cur) => {
      if (!cur) return cur;
      const next = clone(cur);
      setPath(next, path, value);
      return next;
    });
    setDirty(true);
  }

  async function onSave() {
    if (!draft) return;
    if (await saveConfig(draft)) setDirty(false);
  }

  async function onReload() {
    const fresh = await loadConfig();
    if (fresh) {
      setDraft(clone(fresh));
      setDirty(false);
      toast("已从磁盘重新读取配置", "ok");
    }
  }

  async function onTomlLoad() {
    const text = await configToToml();
    if (text === null) return;
    setToml(text);
    setTomlOut("（已从磁盘配置刷新）");
  }

  async function onTomlCheck() {
    const parsed = await configFromToml(toml);
    if (!parsed.ok) {
      setTomlOut(`✗ ${parsed.e}`);
      return;
    }
    const warns = await validateConfig(parsed.v);
    const list = warns.ok ? warns.v : [];
    setTomlOut(
      list.length > 0
        ? `✓ 语法正确，但有 ${list.length} 条告警：\n${list.map((w) => `  ⚠ ${w}`).join("\n")}`
        : "✓ 语法正确，没有告警。",
    );
  }

  async function onTomlApply() {
    const parsed = await configFromToml(toml);
    if (!parsed.ok) {
      toast(`应用失败：${parsed.e}`, "err", 9000);
      return;
    }
    if (await saveConfig(parsed.v)) {
      setDirty(false);
      setTomlOut("✓ 已应用");
      toast("TOML 已应用", "ok");
    }
  }

  return (
    <>
      <Panel
        title="配置"
        hint={
          <>
            改动即时生效并落盘。标 <span className="star">★</span> 的改动（监听端口、绑定地址、SOCKS5
            绑定）需要重启服务。
          </>
        }
        actions={
          <>
            {dirty && <span className="dirty">有未保存的改动</span>}
            <button className="ghost" onClick={() => void onReload()}>
              从磁盘重读
            </button>
            <button className="primary" onClick={() => void onSave()} disabled={!draft}>
              保存并应用
            </button>
          </>
        }
      >
        {!draft ? (
          <div className="empty">配置还没读出来。</div>
        ) : (
          <>
            {CONFIG_SECTIONS.map((section) => (
              <fieldset key={section.title}>
                <legend>{section.title}</legend>
                {section.fields.map((field) => (
                  <Field
                    key={field.path}
                    field={field}
                    value={getPath(draft, field.path)}
                    onChange={(v) => patch(field.path, v)}
                  />
                ))}

                {section.title === "种子与发现" && (
                  <ListEditor
                    title="别名表（peers.entry）"
                    rows={draft.peers.entry}
                    fields={[
                      { key: "address", label: "address", placeholder: "10.1.2.3:20000" },
                      { key: "alias", label: "alias", placeholder: "gpu-01" },
                    ]}
                    empty="没有别名条目。规则里写 alias:<名> 之前，得先在这里登记「别名 → 地址」。"
                    addRow={() => ({ address: "", alias: "" })}
                    onChange={(entry) => patch("peers.entry", entry)}
                  />
                )}

                {section.title === "路由" && (
                  <ListEditor
                    title="候选集（route.groups）"
                    rows={draft.route.groups}
                    fields={[
                      { key: "name", label: "name", placeholder: "db" },
                      {
                        key: "members",
                        label: "members",
                        list: true,
                        placeholder: "10.1.2.3, 10.1.2.4",
                      },
                    ]}
                    empty="没有候选集。规则里写 group:<名> 之前，得先在这里定义成员。"
                    addRow={() => ({ name: "", members: [] })}
                    onChange={(groups) => patch("route.groups", groups)}
                  />
                )}
              </fieldset>
            ))}
          </>
        )}
      </Panel>

      <Panel
        title="高级：直接编辑 TOML"
        hint="表单覆盖不到的内容在这里改。「校验」只检查语法与告警，不会应用。"
      >
        <Row>
          <button className="ghost" onClick={() => void onTomlLoad()}>
            从当前配置刷新
          </button>
          <button onClick={() => void onTomlCheck()}>校验</button>
          <button className="ok" onClick={() => void onTomlApply()}>
            应用
          </button>
          <span className="spacer" />
          <span className="hint mono" style={{ margin: 0 }}>
            {svc.data_dir}
          </span>
        </Row>
        <textarea
          spellCheck={false}
          value={toml}
          onChange={(e) => setToml(e.target.value)}
          placeholder="点上面的「从当前配置刷新」把磁盘上的配置读进来…"
        />
        <pre className="out">{tomlOut}</pre>
      </Panel>
    </>
  );
}

function Field({
  field,
  value,
  onChange,
}: {
  field: ConfigField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  const id = `cf_${field.path.replace(/\./g, "_")}`;
  let input: ReactNode;

  switch (field.type) {
    case "bool":
      input = (
        <input
          id={id}
          type="checkbox"
          checked={Boolean(value)}
          onChange={(e) => onChange(e.target.checked)}
        />
      );
      break;
    case "select":
      input = (
        <select id={id} value={String(value ?? "")} onChange={(e) => onChange(e.target.value)}>
          {(field.options ?? []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      );
      break;
    case "number":
      input = (
        <input
          id={id}
          type="number"
          value={value == null ? "" : String(value)}
          onChange={(e) =>
            onChange(e.target.value === "" ? (field.nullable ? null : 0) : Number(e.target.value))
          }
        />
      );
      break;
    case "numlist":
      input = (
        <input
          id={id}
          value={Array.isArray(value) ? (value as number[]).join(", ") : ""}
          placeholder={field.placeholder}
          onChange={(e) => onChange(splitNums(e.target.value))}
        />
      );
      break;
    case "strlist":
      input = (
        <input
          id={id}
          value={Array.isArray(value) ? (value as string[]).join(", ") : ""}
          placeholder={field.placeholder}
          onChange={(e) => onChange(splitStrs(e.target.value))}
        />
      );
      break;
    default:
      input = (
        <input
          id={id}
          value={value == null ? "" : String(value)}
          placeholder={field.placeholder}
          onChange={(e) =>
            onChange(e.target.value === "" && field.nullable ? null : e.target.value)
          }
        />
      );
  }

  return (
    <div className="field">
      <label htmlFor={id}>
        {field.star ? <span className="star">★ </span> : null}
        {field.label}
      </label>
      <div>{input}</div>
      {field.hint ? <div className="hint">{field.hint}</div> : null}
    </div>
  );
}
