import { useCallback, useRef } from "react";

/**
 * critical 알림 발생 시 짧은 합성음을 재생하는 훅.
 * 외부 오디오 파일 의존 없이 Web Audio API의 오실레이터로 직접 합성한다.
 * 기본 off, 브라우저 자동재생 정책상 사용자 상호작용(unlock) 이후에만 재생 가능.
 */
export function useAlertSound(enabled: boolean) {
  const audioCtxRef = useRef<AudioContext | null>(null);

  const unlock = useCallback(() => {
    if (!audioCtxRef.current) {
      audioCtxRef.current = new AudioContext();
    } else if (audioCtxRef.current.state === "suspended") {
      audioCtxRef.current.resume();
    }
  }, []);

  const playCriticalAlert = useCallback(() => {
    if (!enabled || !audioCtxRef.current) return;
    const ctx = audioCtxRef.current;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = 880;
    gain.gain.setValueAtTime(0.15, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.2);
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.2);
  }, [enabled]);

  return { unlock, playCriticalAlert };
}
