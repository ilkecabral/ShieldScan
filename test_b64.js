function base64urlToBuffer(b64url) {
  const b64 = (b64url || "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64.padEnd(b64.length + (4 - b64.length % 4) % 4, "=");
  const raw = atob(padded);
  console.log("Success");
}
base64urlToBuffer("90Kdzq49Hl75lQNIs8ZiKj2YDoEjBUAFNs7Em8y0OPGQKe6fWk4QW6PYY8wE8-XA8Qi_mbiC1I4UlufKy9NJvg");
