import { computed, onUnmounted, ref, shallowRef, unref } from 'vue'
import type { MaybeRef } from 'vue'
import * as AsciinemaPlayer from 'asciinema-player'
import * as sessionsApi from '@/api/sessions'
import type { Player, PlayerSource } from 'asciinema-player'
import type { Session, SessionRecording } from '@/types'

const DEFAULT_SPEED = 1

export function useSessionReplay(sessionId: MaybeRef<number>) {
  const loading = ref(false)
  const playerLoading = ref(false)
  const error = ref<string | null>(null)
  const session = ref<Session | null>(null)
  const recording = ref<SessionRecording | null>(null)
  const player = shallowRef<Player | null>(null)
  const currentTime = ref(0)
  const duration = ref(0)
  const isPlaying = ref(false)
  const speed = ref(DEFAULT_SPEED)
  let progressTimer: ReturnType<typeof globalThis.setInterval> | undefined

  const sourceUrl = computed(() => recording.value?.url || recording.value?.download_url || '')
  const downloadUrl = computed(() => recording.value?.download_url || recording.value?.url || '')
  const available = computed(() => recording.value?.available === true && !!sourceUrl.value)

  function isLocalAPIRecording(url: string): boolean {
    return url.startsWith('/api/v1/sessions/')
  }

  function stopProgressTimer() {
    if (progressTimer !== undefined) {
      globalThis.clearInterval(progressTimer)
      progressTimer = undefined
    }
  }

  function startProgressTimer() {
    stopProgressTimer()
    progressTimer = globalThis.setInterval(() => {
      void refreshProgress()
    }, 300)
  }

  async function refreshProgress() {
    if (!player.value) return
    try {
      const [time, total] = await Promise.all([
        player.value.getCurrentTime(),
        player.value.getDuration(),
      ])
      currentTime.value = Math.max(0, time)
      duration.value = Math.max(0, total ?? duration.value)
    } catch {
      // Keep the last known progress when the player is between lifecycle states.
    }
  }

  function destroyPlayer() {
    stopProgressTimer()
    if (player.value) {
      player.value.dispose()
      player.value = null
    }
    isPlaying.value = false
    currentTime.value = 0
    duration.value = 0
  }

  async function load() {
    loading.value = true
    error.value = null
    try {
      const [sessionData, recordingData] = await Promise.all([
        sessionsApi.get(unref(sessionId)),
        sessionsApi.recording(unref(sessionId)),
      ])
      session.value = sessionData
      recording.value = recordingData
      if (!recordingData.available || (!recordingData.url && !recordingData.download_url)) {
        error.value = '录像文件不可用'
      }
    } catch (err: unknown) {
      error.value = err instanceof Error ? err.message : '加载录像失败'
    } finally {
      loading.value = false
    }
  }

  async function mount(container: HTMLElement) {
    if (!available.value || !sourceUrl.value) return
    destroyPlayer()
    playerLoading.value = true
    container.replaceChildren()
    try {
      let source: PlayerSource = sourceUrl.value
      if (isLocalAPIRecording(sourceUrl.value)) {
        const content = await sessionsApi.downloadRecordingContent(unref(sessionId))
        source = { data: content }
      }
      const instance = AsciinemaPlayer.create(source, container, {
        autoPlay: false,
        controls: true,
        fit: 'width',
        speed: speed.value,
        theme: 'asciinema',
      })
      player.value = instance
      instance.addEventListener('play', () => {
        isPlaying.value = true
        startProgressTimer()
      })
      instance.addEventListener('playing', () => {
        isPlaying.value = true
        startProgressTimer()
      })
      instance.addEventListener('pause', () => {
        isPlaying.value = false
        void refreshProgress()
        stopProgressTimer()
      })
      instance.addEventListener('ended', () => {
        isPlaying.value = false
        void refreshProgress()
        stopProgressTimer()
      })
      instance.addEventListener('seeked', () => {
        void refreshProgress()
      })
      await refreshProgress()
    } catch (err: unknown) {
      error.value = err instanceof Error ? err.message : '初始化播放器失败'
    } finally {
      playerLoading.value = false
    }
  }

  async function play() {
    if (!player.value) return
    await player.value.play()
    isPlaying.value = true
    startProgressTimer()
  }

  async function pause() {
    if (!player.value) return
    await player.value.pause()
    isPlaying.value = false
    await refreshProgress()
    stopProgressTimer()
  }

  async function seek(position: number) {
    if (!player.value) return
    await player.value.seek(position)
    await refreshProgress()
  }

  onUnmounted(destroyPlayer)

  return {
    loading,
    playerLoading,
    error,
    session,
    recording,
    currentTime,
    duration,
    isPlaying,
    speed,
    sourceUrl,
    downloadUrl,
    available,
    load,
    mount,
    play,
    pause,
    seek,
    destroyPlayer,
  }
}
