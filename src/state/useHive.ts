// 订阅 hook。一个 store 一个 —— 组件只订阅自己真正要用的那几份数据，
// 引擎每秒一条的 stats 就不会把日志页、规则页一起重渲染。

import * as hive from "./hive";
import { useStore } from "./store";

export const useService = () => useStore(hive.serviceStore);
export const useStatus = () => useStore(hive.statusStore);
export const useStats = () => useStore(hive.statsStore);
export const useTopology = () => useStore(hive.topologyStore);
export const useStreams = () => useStore(hive.streamsStore);
export const useZones = () => useStore(hive.zonesStore);
export const useGroups = () => useStore(hive.groupsStore);
export const useRulesView = () => useStore(hive.rulesViewStore);
export const useRuleStats = () => useStore(hive.ruleStatsStore);
export const useShared = () => useStore(hive.sharedStore);
export const useConfig = () => useStore(hive.configStore);
export const useRuleDraft = () => useStore(hive.ruleDraftStore);
export const useLogs = () => useStore(hive.logStore);
export const useToasts = () => useStore(hive.toastStore);
