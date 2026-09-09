import { createContext, useContext } from "react";
import type { Session } from "./api";
import type { CommandData } from "./useCommandData";
export interface CommandContextValue {
  session: Session;
  data: CommandData;
  scenarioId: string;
  navigate: (route: string, entity?: string) => void;
  inspectEvent: (id: string) => void;
  inspectAsset: (id: string) => void;
  entity: string;
  notify: (message: string) => void;
}
export const CommandContext = createContext<CommandContextValue | null>(null);
export function useCommand() {
  const value = useContext(CommandContext);
  if (!value) throw new Error("Command context required");
  return value;
}
