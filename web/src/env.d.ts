/// <reference types="vite/client" />

declare module '*.css' {}
declare module '*.scss' {}
declare module 'asciinema-player' {
  export interface PlayerOptions {
    autoPlay?: boolean
    autoplay?: boolean
    controls?: boolean | 'auto'
    fit?: false | 'none' | 'width' | 'height' | 'both'
    idleTimeLimit?: number
    poster?: string
    speed?: number
    startAt?: number
    terminalFontSize?: number
    theme?: string
  }

  export interface Player {
    el: HTMLElement
    dispose(): void
    getCurrentTime(): Promise<number>
    getDuration(): Promise<number | undefined>
    play(): Promise<boolean | undefined>
    pause(): Promise<boolean | undefined>
    seek(position: number | string): Promise<boolean | undefined>
    addEventListener(name: string, callback: (event?: unknown) => void): void
  }

  export type PlayerSource = string | { url?: string; data?: string | ArrayBuffer | (() => string | ArrayBuffer | Promise<string | ArrayBuffer>) }

  export function create(src: PlayerSource, elem: HTMLElement, opts?: PlayerOptions): Player
}
declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<object, object, unknown>
  export default component
}
