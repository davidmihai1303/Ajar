// "About you": optional details the local assistant uses to explain things at the user's level.
import { useState } from "react";
import type { UserProfile } from "../api/types";
import { AGES, PROFESSION_MAX, TECH, emptyProfile, normalizeProfile } from "../lib/profile";
import { useApp } from "../state/AppState";
import Dialog from "./Dialog";

interface Props {
  profile: UserProfile;
  onSave: (profile: UserProfile) => void;
  onClose: () => void;
}

export default function ProfileDialog({ profile, onSave, onClose }: Props) {
  const { t } = useApp();
  const [draft, setDraft] = useState<UserProfile>(profile);
  const save = (value: UserProfile) => {
    onSave(normalizeProfile(value));
    onClose();
  };

  return (
    <Dialog
      title={t("profile.title")}
      onCancel={onClose}
      actions={
        <>
          <button type="button" className="button" data-autofocus onClick={onClose}>
            {t("common.cancel")}
          </button>
          <button type="button" className="button" onClick={() => save(emptyProfile())}>
            {t("profile.clear")}
          </button>
          <button type="button" className="button primary" onClick={() => save(draft)}>
            {t("profile.save")}
          </button>
        </>
      }
    >
      <form
        className="stack gap-m profile-form"
        onSubmit={(event) => {
          event.preventDefault();
          save(draft);
        }}
      >
        <p className="dialog-body">{t("profile.intro")}</p>
        <label className="field">
          <span>{t("profile.age")}</span>
          <select value={draft.age ?? ""} onChange={(event) => setDraft({ ...draft, age: (event.target.value || null) as UserProfile["age"] })}>
            <option value="">{t("profile.none")}</option>
            {AGES.map((age) => (
              <option key={age} value={age}>{t("profile.age." + age)}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("profile.tech")}</span>
          <select value={draft.tech ?? ""} onChange={(event) => setDraft({ ...draft, tech: (event.target.value || null) as UserProfile["tech"] })}>
            <option value="">{t("profile.none")}</option>
            {TECH.map((level) => (
              <option key={level} value={level}>{t("profile.tech." + level)}</option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>{t("profile.profession")}</span>
          <input
            type="text"
            value={draft.profession}
            maxLength={PROFESSION_MAX}
            placeholder={t("profile.professionHint")}
            autoComplete="organization-title"
            onChange={(event) => setDraft({ ...draft, profession: event.target.value })}
          />
        </label>
      </form>
    </Dialog>
  );
}
