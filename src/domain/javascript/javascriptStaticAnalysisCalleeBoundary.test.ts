import { describe, expect, it } from "vitest";

import { analyzeJavaScriptStaticSource } from "./javascriptStaticAnalysis.js";

const project = (source: string) => {
  const analysis = analyzeJavaScriptStaticSource(source);
  return {
    status: analysis.parse_status,
    roles: analysis.role_paths.map(({ role, path, mechanism }) => ({
      role,
      path,
      mechanism,
    })),
    references: analysis.references.map(({ kind, specifier }) => ({
      kind,
      specifier,
    })),
    endpoints: analysis.endpoints.map(({ kind, value, mechanism }) => ({
      kind,
      value,
      mechanism,
    })),
  };
};

describe("Electron callee member boundaries", () => {
  it("keeps exact and dotted loadFile, loadURL, and serviceWorker.register calls", () => {
    expect(
      project(`
        loadFile("./bare.html");
        win.loadFile("./renderer/index.html");
        app.win.loadFile("./nested.html");
        loadURL("https://bare.example.test/");
        BrowserWindow.loadURL("https://app.example.test/page");
        win?.loadURL("https://optional.example.test/");
        serviceWorker.register("./bare-sw.js");
        navigator.serviceWorker.register("./sw.js");
      `),
    ).toEqual({
      status: "complete",
      roles: [
        {
          role: "renderer",
          path: "./bare.html",
          mechanism: "call:loadFile",
        },
        {
          role: "renderer",
          path: "./renderer/index.html",
          mechanism: "call:win.loadFile",
        },
        {
          role: "renderer",
          path: "./nested.html",
          mechanism: "call:app.win.loadFile",
        },
        {
          role: "renderer",
          path: "https://bare.example.test/",
          mechanism: "call:loadURL",
        },
        {
          role: "renderer",
          path: "https://app.example.test/page",
          mechanism: "call:BrowserWindow.loadURL",
        },
        {
          role: "renderer",
          path: "https://optional.example.test/",
          mechanism: "call:win.loadURL",
        },
      ],
      references: [
        { kind: "service-worker", specifier: "./bare-sw.js" },
        { kind: "service-worker", specifier: "./sw.js" },
      ],
      endpoints: [
        {
          kind: "network",
          value: "https://bare.example.test/",
          mechanism: "call:loadURL",
        },
        {
          kind: "network",
          value: "https://app.example.test/page",
          mechanism: "call:BrowserWindow.loadURL",
        },
        {
          kind: "network",
          value: "https://optional.example.test/",
          mechanism: "call:win.loadURL",
        },
      ],
    });
  });

  it("does not treat a shared identifier suffix as an Electron callee", () => {
    expect(
      project(`
        uploadFile("./secret.html");
        preloadFile("./also.html");
        loadFileBackup("./nope.html");
        downloadURL("https://cdn.example.test/app");
        reloadURL("https://cdn.example.test/other");
        notloadURL("https://cdn.example.test/nope");
        myserviceWorker.register("./nope.js");
        serviceWorker.registerExtra("./nope.js");
      `),
    ).toEqual({
      status: "complete",
      roles: [],
      references: [],
      endpoints: [],
    });
  });

  it("keeps exact bracket members and rejects a dot inside one computed key", () => {
    expect(
      project(`
        win["loadFile"]("./renderer/index.html");
        win["loadURL"]("https://app.example.test/page");
        navigator["serviceWorker"].register("./sw.js");
        navigator.serviceWorker["register"]("./other-sw.js");
      `),
    ).toEqual({
      status: "complete",
      roles: [
        {
          role: "renderer",
          path: "./renderer/index.html",
          mechanism: "call:win.loadFile",
        },
        {
          role: "renderer",
          path: "https://app.example.test/page",
          mechanism: "call:win.loadURL",
        },
      ],
      references: [
        { kind: "service-worker", specifier: "./sw.js" },
        { kind: "service-worker", specifier: "./other-sw.js" },
      ],
      endpoints: [
        {
          kind: "network",
          value: "https://app.example.test/page",
          mechanism: "call:win.loadURL",
        },
      ],
    });
    expect(
      project(`
        api["fake.loadFile"]("./secret.html");
        api["fake.loadURL"]("https://cdn.example.test/app");
        api["fake.serviceWorker.register"]("./nope.js");
        api["serviceWorker.register"]("./also-nope.js");
      `),
    ).toEqual({
      status: "complete",
      roles: [],
      references: [],
      endpoints: [],
    });
  });
});
