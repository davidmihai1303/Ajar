// While a scan runs: a few door-themed words take turns, instead of a plain "Scanning...".
import { useEffect, useState } from "react";
import { useApp } from "../state/AppState";

const WORDS = ["scan.word.knock", "scan.word.keyhole", "scan.word.listen", "scan.word.hinges", "scan.word.ajar"];
const CHANGE_MS = 2800;

export default function ScanWord() {
  const { t } = useApp();
  const [index, setIndex] = useState(0);
  useEffect(() => {
    const timer = window.setInterval(() => setIndex((value) => (value + 1) % WORDS.length), CHANGE_MS);
    return () => window.clearInterval(timer);
  }, []);
  return (
    <span key={index} className="scan-word">
      {t(WORDS[index])}
    </span>
  );
}
