// 极小的外部状态容器：一个值 + 一组订阅者。
//
// 为什么不用 useState 全局 Context：引擎的事件（每秒 1 条 stats、拓扑变化时的
// topology、实时 log）来自 React 之外的广播通道。放到一个 Context 里会让每次
// stats 刷新都把整棵树重新渲染一遍；拆成多个独立的 store 之后，只有真正关心
// 那一份数据的组件会重渲染。
//
// `useSyncExternalStore` 是 React 官方的"订阅外部数据源"原语，天然避开
// 撕裂（tearing）与并发渲染下的不一致。

import { useSyncExternalStore } from "react";

export interface Store<T> {
  get(): T;
  set(next: T | ((prev: T) => T)): void;
  /** 只在值真的变了的时候触发订阅者。 */
  patch(updater: (prev: T) => T): void;
  subscribe(fn: () => void): () => void;
}

export function createStore<T>(initial: T, equal: (a: T, b: T) => boolean = Object.is): Store<T> {
  let state = initial;
  const subs = new Set<() => void>();

  const emit = () => {
    for (const fn of subs) fn();
  };

  return {
    get: () => state,
    set(next) {
      const value = typeof next === "function" ? (next as (p: T) => T)(state) : next;
      if (equal(state, value)) return;
      state = value;
      emit();
    },
    patch(updater) {
      const value = updater(state);
      if (equal(state, value)) return;
      state = value;
      emit();
    },
    subscribe(fn) {
      subs.add(fn);
      return () => {
        subs.delete(fn);
      };
    },
  };
}

export function useStore<T>(store: Store<T>): T {
  return useSyncExternalStore(store.subscribe, store.get, store.get);
}

/** 浅比较：用于"值是一个扁平对象"的 store（例如服务状态）。 */
export function shallowEqual<T extends object>(a: T, b: T): boolean {
  if (Object.is(a, b)) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  for (const k of ka) {
    if (!Object.is((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k])) return false;
  }
  return true;
}
