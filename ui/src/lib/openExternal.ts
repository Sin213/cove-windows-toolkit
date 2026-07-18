import { invoke } from "./tauri";

interface OpenUrlResponse {
  success?: boolean;
  message?: string;
}

export type OpenExternalResult = { ok: true } | { ok: false; message: string };

/** Open an https:// URL in the user's default browser via the backend
 *  `open_url` command. Handles both a rejected invocation and a
 *  `{ success: false }` response. */
export async function openExternal(url: string): Promise<OpenExternalResult> {
  try {
    const res = await invoke<OpenUrlResponse>("open_url", { url });
    if (res?.success) return { ok: true };
    return { ok: false, message: res?.message ?? "The link could not be opened." };
  } catch (e) {
    return { ok: false, message: String(e) };
  }
}
