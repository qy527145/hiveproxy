import { dismissToast } from "../state/hive";
import { useToasts } from "../state/useHive";

/** 右下角的一次性提示。点一下即消。 */
export function Toasts() {
  const toasts = useToasts();
  if (toasts.length === 0) return null;
  return (
    <div id="toast">
      {toasts.map((t) => (
        <div key={t.id} className={t.kind} onClick={() => dismissToast(t.id)}>
          {t.msg}
        </div>
      ))}
    </div>
  );
}
