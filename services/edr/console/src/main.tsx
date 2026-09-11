import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { WorkspaceBar } from "@cyber-range/command-system";
import "@cyber-range/command-system/tokens.css";
import "@cyber-range/command-system/styles.css";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <div className="edr-root">
      <WorkspaceBar workspace="Endpoint Defense" />
      <App />
    </div>
  </React.StrictMode>
);
