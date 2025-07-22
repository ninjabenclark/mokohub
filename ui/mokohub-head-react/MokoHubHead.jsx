import React, { useState, useEffect, useRef, useCallback } from 'react';
import MokoEngine from "./MokoEngine";

export default function MokoHubHead() {
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState([]);

  const handleSend = useCallback(async () => {
    if (!input.trim()) return;
    const userMessage = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { sender: "You", text: userMessage }]);

    const reply = await MokoEngine(userMessage);
    setMessages((prev) => [...prev, { sender: "MokoHub", text: reply }]);
  }, [input]);

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      <h1 className="text-4xl font-bold mb-4">MokoHub</h1>
      <div className="space-y-2 mb-4">
        {messages.map((msg, idx) => (
          <div key={idx} className="bg-white p-3 rounded shadow">
            <strong>{msg.sender}:</strong> {msg.text}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        <input
          className="flex-grow p-2 rounded border"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
        />
        <button className="bg-blue-500 text-white px-4 py-2 rounded" onClick={handleSend}>
          Send
        </button>
      </div>
    </div>
  );
}
