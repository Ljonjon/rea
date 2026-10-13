import type { JavaScriptSourceSelection } from "./javascriptSourceSelection.js";

/** Relevant file categories projected from the complete artifact inventory. */
export type JavaScriptArtifactFileKind =
  | "package-json"
  | "json"
  | "javascript"
  | "html"
  | "source-map"
  | "native-addon"
  | "unsupported";

/** One content-addressed local artifact file and its text availability. */
export interface JavaScriptArtifactFile {
  readonly path: string;
  readonly container_sha256: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly inventory_artifact_id: string;
  readonly kind: JavaScriptArtifactFileKind;
  readonly unpacked: boolean;
  readonly text:
    | { readonly included: true; readonly value: string }
    | {
        readonly included: false;
        readonly reason:
          | "not-applicable"
          | "invalid-utf8"
          | "outside-analysis-scope";
      };
}

/** Inventoried path whose bytes and content identity could not be acquired. */
export interface JavaScriptArtifactUnavailableFile {
  readonly path: string;
  readonly container_sha256: string;
  readonly kind: JavaScriptArtifactFileKind;
  readonly text: { readonly included: false; readonly reason: "unavailable" };
}

export type JavaScriptArtifactPathFact =
  | JavaScriptArtifactFile
  | JavaScriptArtifactUnavailableFile;

/** One filesystem-backed ASAR nested beneath a directory input. */
export interface JavaScriptArtifactContainer {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly inventory_artifact_id: string;
}

/** Deterministic relevant-file projection plus explicit omissions. */
export interface JavaScriptArtifactFileSet {
  readonly files: readonly JavaScriptArtifactFile[];
  readonly unavailable_files?: readonly JavaScriptArtifactUnavailableFile[];
  readonly containers: readonly JavaScriptArtifactContainer[];
  readonly text_bytes_read: number;
  readonly invalid_utf8_files: number;
  readonly source_selection?: JavaScriptSourceSelection;
}
