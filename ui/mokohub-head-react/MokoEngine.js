export default async function MokoEngine(message) {
  try {
    const response = await fetch("https://api.mokohub.ai/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer YOUR_API_KEY_HERE"
      },
      body: JSON.stringify({ prompt: message }),
    });

    const result = await response.json();
    return result.reply || "No response.";
  } catch (err) {
    console.error(err);
    return "Error communicating with MokoEngine.";
  }
}
