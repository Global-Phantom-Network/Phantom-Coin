import { createContext, useContext } from 'react';
import type { DashboardTexts, Locale } from './types';
import { en } from './en';
import { isTauri } from '../tauri-bridge';

export type { DashboardTexts, Locale };
export { LOCALE_NAMES } from './types';

const ALL_LOCALES: readonly Locale[] = ['de','en','es','fr','it','pt','nl','ru','zh','ja','ko','tr','ar','pl'];

export const FALLBACK_TEXTS: DashboardTexts = en;

export async function fetchTexts(locale: Locale): Promise<DashboardTexts> {
  if (isTauri) {
    try {
      const { invoke } = await import('@tauri-apps/api/tauri');
      return await invoke<DashboardTexts>('get_dashboard_texts', { lang: locale });
    } catch (e) {
      console.warn('[i18n] invoke get_dashboard_texts failed, using fallback:', e);
    }
  }
  return FALLBACK_TEXTS;
}

const I18nContext = createContext<{ t: DashboardTexts; locale: Locale; setLocale: (l: Locale) => void }>({
  t: FALLBACK_TEXTS,
  locale: 'de',
  setLocale: () => {},
});

export const I18nProvider = I18nContext.Provider;

export function useI18n() {
  return useContext(I18nContext);
}

const LOCALE_KEY = 'phantom.dashboard.locale';

export function loadLocale(): Locale {
  try {
    const v = localStorage.getItem(LOCALE_KEY);
    if (v && ALL_LOCALES.includes(v as Locale)) return v as Locale;
  } catch { /* ignore */ }
  return 'de';
}

export function saveLocale(locale: Locale): void {
  try {
    localStorage.setItem(LOCALE_KEY, locale);
  } catch { /* ignore */ }
}
