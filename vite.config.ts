import { defineConfig } from "vite";

// 这个前端**刻意不引入 @vitejs/plugin-react**：
// Vite 内建的 esbuild 转换本身就支持 .tsx（下面显式钉住 automatic JSX runtime），
// 少的这一个依赖换来的是"离线也能装、也能构建"。代价只是没有 Fast Refresh ——
// dev 下改组件会整页刷新，而不是热替换。
// 需要热替换时：`bun add -d @vitejs/plugin-react && bun add -d react-refresh`，
// 再把 `plugins: [react()]` 加回来即可，其余配置不用动。
export default defineConfig({
  esbuild: { jsx: "automatic" },
  // Tauri 的 CLI 自己会打印构建日志，别让 vite 清屏把 Rust 的报错冲掉
  clearScreen: false,
  server: {
    // 与 src-tauri/tauri.conf.json 的 devUrl 必须一致
    port: 1420,
    strictPort: true,
    host: false,
    hmr: { protocol: "ws", host: "localhost", port: 1421 },
    watch: {
      // Rust 侧的改动由 tauri dev 自己盯着，别让 vite 跟着重建前端
      ignored: ["**/src-tauri/**", "**/crates/**", "**/target/**"],
    },
  },
  build: {
    // WKWebView / WebView2 都吃得下 ES2020，不需要为更老的目标降级
    target: "es2020",
    sourcemap: false,
  },
});
