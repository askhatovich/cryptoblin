export const de = {
    app: {
        title: 'CryptoBlin',
        subtitle: 'Zero-Knowledge-Notizfreigabe: Inhalte werden im Browser verschlüsselt, bevor sie den Server erreichen',
        privacy_blurb: 'Ende-zu-Ende-Verschlüsselung mit XChaCha20-Poly1305 und Argon2id-Schlüsselableitung. Der Schlüssel wird im Browser des Absenders erzeugt und reist im URL-Fragment, das niemals an den Server gesendet wird. Der Server speichert ausschließlich den Geheimtext und kann den Inhalt der Notiz nicht lesen.'
    },
    nav: {
        new_paste: 'Neue Notiz',
        github: 'Quellcode'
    },
    create: {
        format: 'Format',
        format_text: 'Klartext',
        format_markdown: 'Markdown',
        format_code: 'Quellcode',
        language: 'Sprache',
        body_placeholder: 'Inhalt hier eingeben oder einfügen…',
        attach_file: 'Datei anhängen — hierhin ziehen oder klicken',
        remove_file: 'Entfernen',
        burn: 'Nach erstem Lesen löschen',
        burn_hint: 'Die Notiz wird in dem Moment vernichtet, in dem sie geöffnet wird',
        password: 'Passwort',
        password_placeholder: 'optional',
        password_hint: 'Setze ein Passwort, wenn der Link über einen weniger vertrauenswürdigen Kanal geteilt wird. Das Passwort erreicht den Server nie.',
        submit: 'Notiz erstellen',
        submitting: 'Wird hochgeladen…',
        phase_captcha: 'Proof-of-Work wird angefordert…',
        phase_pow: 'Captcha wird gelöst ({tries})…',
        phase_encrypting: 'Wird verschlüsselt…',
        ttl_estimate: 'Geschätzte Lebensdauer: {duration}',
        size_used: '{size} von {limit}',
        too_large: 'Inhalt ist zu groß. Maximum ist {limit}.'
    },
    result: {
        title: 'Notiz erstellt',
        copy: 'Link kopieren',
        copied: 'Link kopiert',
        copy_failed: 'Kopieren fehlgeschlagen',
        qr: 'QR-Code anzeigen',
        qr_title: 'Zum Öffnen scannen',
        qr_close: 'Schließen',
        new: 'Neue Notiz erstellen',
        ttl_remaining: 'Selbstzerstörung in {duration}',
        burn_warning: 'Diese Notiz löscht sich selbst beim ersten Öffnen',
        password_set: 'Zum Öffnen dieser Notiz wird ein Passwort benötigt',
        delete: 'Löschen'
    },
    delete: {
        working: 'Notiz wird gelöscht…',
        ok: 'Notiz gelöscht',
        fail: 'Notiz konnte nicht gelöscht werden'
    },
    view: {
        loading: 'Wird entschlüsselt…',
        password_required: 'Diese Notiz ist passwortgeschützt',
        password_input: 'Passwort',
        password_submit: 'Entsperren',
        password_wrong: 'Falsches Passwort',
        burn_warning_title: 'Nach dem Lesen vernichten',
        burn_warning_body: 'Diese Notiz wird in dem Moment vernichtet, in dem du sie öffnest. Sichere alle nötigen Informationen jetzt — nach dem Neuladen der Seite sind die Daten nicht mehr verfügbar.',
        burn_continue: 'Öffnen und vernichten',
        burn_cancel: 'Abbrechen',
        download_file: 'Datei herunterladen',
        copy_text: 'Text kopieren',
        copied: 'Kopiert',
        copy_failed: 'Kopieren fehlgeschlagen',
        save_text_as_file: 'Text als Datei speichern',
        show_raw: 'Quelltext anzeigen',
        create_copy: 'Kopie erstellen',
        meta_size: 'Größe',
        meta_created: 'Erstellt',
        meta_expires: 'Läuft ab in',
        meta_views: 'Aufrufe',
        loading_meta: 'Wird geladen…'
    },
    errors: {
        not_found: 'Diese Notiz existiert nicht oder ist abgelaufen',
        rate_limited: 'Zu viele Captcha-Anfragen. Bitte gleich nochmal versuchen.',
        pow_required: 'Proof-of-Work fehlt',
        pow_invalid: 'Proof-of-Work-Signatur ist ungültig',
        pow_expired: 'Proof-of-Work abgelaufen — bitte erneut versuchen',
        pow_insufficient: 'Proof-of-Work war unzureichend',
        pow_replayed: 'Proof-of-Work wurde bereits verwendet',
        too_large: 'Inhalt ist größer als der Server erlaubt',
        capacity_full: 'Der Server ist ausgelastet. Bitte später erneut versuchen.',
        bad_envelope: 'Der Link ist beschädigt',
        bad_key: 'Falscher Schlüssel oder falsches Passwort. Der Link könnte fehlerhaft sein.',
        network: 'Netzwerkfehler',
        internal: 'Serverfehler'
    },
    units: {
        second_one: 'Sekunde', second_few: 'Sekunden', second_many: 'Sekunden',
        minute_one: 'Minute',  minute_few: 'Minuten',  minute_many: 'Minuten',
        hour_one:   'Stunde',  hour_few:   'Stunden',  hour_many:   'Stunden',
        day_one:    'Tag',     day_few:    'Tage',     day_many:    'Tage'
    }
};
