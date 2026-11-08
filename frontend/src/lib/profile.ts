// The user's optional self-description for Ask (age range, tech familiarity, profession).
// Kept only in this browser (localStorage) and sent with Ask questions to the local AI.
import type { AgeRange, TechLevel, UserProfile } from "../api/types";

const KEY = "ajar.profile";
export const AGES: AgeRange[] = ["under_18", "18_29", "30_49", "50_64", "65_plus"];
export const TECH: TechLevel[] = ["beginner", "intermediate", "advanced"];
export const PROFESSION_MAX = 60;

export const emptyProfile = (): UserProfile => ({ age: null, tech: null, profession: "" });

export function isEmptyProfile(profile: UserProfile): boolean {
  return !profile.age && !profile.tech && !profile.profession.trim();
}

/** Only known values survive, so an edited or outdated stored value cannot break a request. */
export function normalizeProfile(raw: unknown): UserProfile {
  const value = (raw && typeof raw === "object" ? raw : {}) as Partial<Record<keyof UserProfile, unknown>>;
  return {
    age: AGES.includes(value.age as AgeRange) ? (value.age as AgeRange) : null,
    tech: TECH.includes(value.tech as TechLevel) ? (value.tech as TechLevel) : null,
    profession: typeof value.profession === "string" ? Array.from(value.profession.replace(/\s+/g, " ").trim()).slice(0, PROFESSION_MAX).join("") : "",
  };
}

export function loadProfile(): UserProfile {
  try {
    return normalizeProfile(JSON.parse(window.localStorage.getItem(KEY) ?? "null"));
  } catch {
    return emptyProfile();
  }
}

export function saveProfile(profile: UserProfile): void {
  try {
    if (isEmptyProfile(profile)) window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, JSON.stringify(profile));
  } catch {
    /* the profile still applies for this visit */
  }
}
