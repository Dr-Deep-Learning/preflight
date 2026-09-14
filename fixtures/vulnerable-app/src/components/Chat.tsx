import { useState } from "react";

const OPENAI_API_KEY = "sk-preflightFIXTUREkeyDoNotUse7f3a91c4b8e2d6";

export function Chat() {
  const [reply, setReply] = useState("");

  async function send(prompt: string) {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const data = await res.json();
    setReply(data.choices[0].message.content);
  }

  return (
    <div>
      <button onClick={() => send("hello")}>Send</button>
      <p>{reply}</p>
    </div>
  );
}
