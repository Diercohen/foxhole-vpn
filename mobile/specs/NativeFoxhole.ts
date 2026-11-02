// The app's native side (FoxholeModule.kt, ios/Foxhole/FoxholeModule.mm): Foxhole's core runs there, in Node, a line of
// JSON at a time each way.
import type { CodegenTypes, TurboModule } from "react-native";
import { TurboModuleRegistry } from "react-native";

export interface Spec extends TurboModule {
  /** Starts the core, once (it outlives the screen while connected); its lines come as onLine. */
  start(): void;
  /** A line of JSON to the core. */
  send(line: string): void;
  /** The WebView the window runs in, as "<package> <version>" (e.g. "com.android.chrome 138.0.7204.179"); "" if unknown (iOS). */
  webView(): string;
  /** The window's page, a file URL among the app's own files (scripts/prepare.mjs puts it there). */
  page(): string;
  /** The back button with nothing left to close: the app goes to the background, still connected. */
  moveToBack(): void;
  readonly onLine: CodegenTypes.EventEmitter<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>("Foxhole");
