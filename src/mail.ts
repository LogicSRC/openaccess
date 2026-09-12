/**
 * The one mail a hub sends: a sign-in link. Resend when a key is present;
 * otherwise the link is logged, which is how a local hub is used.
 */
export interface Mailer {
  send(input: { to: string; subject: string; text: string; html?: string }): Promise<{ ok: boolean; error?: string }>;
}

export function resendMailer(apiKey: string, from: string, fetcher: typeof fetch = fetch): Mailer {
  return {
    async send(input) {
      try {
        const response = await fetcher("https://api.resend.com/emails", {
          method: "POST",
          headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
          body: JSON.stringify({ from, to: [input.to], subject: input.subject, text: input.text, ...(input.html ? { html: input.html } : {}) }),
        });
        if (!response.ok) return { ok: false, error: `Resend answered ${response.status}: ${(await response.text()).slice(0, 200)}` };
        return { ok: true };
      } catch (error) {
        return { ok: false, error: (error as Error).message };
      }
    },
  };
}

export function logMailer(log: (line: string) => void): Mailer {
  return {
    async send(input) {
      log(`mail to ${input.to}: ${input.subject}\n${input.text}`);
      return { ok: true };
    },
  };
}
