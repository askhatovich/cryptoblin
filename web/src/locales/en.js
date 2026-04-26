export const en = {
    app: {
        title: 'CryptoBlin',
        subtitle: 'Zero-knowledge paste sharing. Your content is encrypted in the browser before it ever reaches the server.',
        privacy_blurb: 'End-to-end XChaCha20-Poly1305 encryption with Argon2id key derivation. The key is generated in the sender\'s browser and travels in the URL fragment, which is never sent to the server. The server stores only ciphertext and cannot read your notes.'
    },
    nav: {
        new_paste: 'New paste',
        github: 'Source'
    },
    create: {
        format: 'Format',
        format_text: 'Plain text',
        format_markdown: 'Markdown',
        format_code: 'Source code',
        language: 'Language',
        body_placeholder: 'Type or paste your content here…',
        attach_file: 'Attach a file — drop here or click to choose',
        remove_file: 'Remove',
        burn: 'Delete after first read',
        burn_hint: 'The note is destroyed the moment someone opens it',
        password: 'Password',
        password_placeholder: 'optional',
        password_hint: 'Set a password if you plan to share the link over a less-trusted channel. The password never reaches the server.',
        submit: 'Create note',
        submitting: 'Uploading…',
        phase_captcha: 'Fetching proof-of-work…',
        phase_pow: 'Solving captcha ({tries})…',
        phase_encrypting: 'Encrypting…',
        ttl_estimate: 'Estimated lifetime: {duration}',
        size_used: '{size} of {limit}',
        too_large: 'Content is too large. Maximum is {limit}.'
    },
    result: {
        title: 'Note created',
        copy: 'Copy link',
        copied: 'Link copied',
        copy_failed: 'Copy failed',
        qr: 'Show QR code',
        qr_title: 'Scan to open',
        qr_close: 'Close',
        new: 'Create new note',
        ttl_remaining: 'Self-destructs in {duration}',
        burn_warning: 'This note deletes itself the first time it is opened',
        password_set: 'A password is required to open this note',
        delete: 'Delete'
    },
    delete: {
        working: 'Deleting the note…',
        ok: 'Note deleted',
        fail: 'Could not delete the note'
    },
    view: {
        loading: 'Decrypting…',
        password_required: 'This note is password-protected',
        password_input: 'Password',
        password_submit: 'Unlock',
        password_wrong: 'Wrong password',
        burn_warning_title: 'Burn after reading',
        burn_warning_body: 'This note is destroyed the moment you open it. Save anything you need now — after reloading the page the data will no longer be available.',
        burn_continue: 'Open and destroy',
        burn_cancel: 'Cancel',
        download_file: 'Download file',
        copy_text: 'Copy text',
        copied: 'Copied',
        copy_failed: 'Copy failed',
        save_text_as_file: 'Save text as file',
        show_raw: 'Show raw text',
        create_copy: 'Create copy',
        meta_size: 'Size',
        meta_created: 'Created',
        meta_expires: 'Expires in',
        meta_views: 'Views',
        loading_meta: 'Loading…'
    },
    errors: {
        not_found: 'This note does not exist or has expired',
        rate_limited: 'Too many captcha requests. Try again in a moment.',
        pow_required: 'Proof-of-work missing',
        pow_invalid: 'Proof-of-work signature is invalid',
        pow_expired: 'Proof-of-work expired — please retry',
        pow_insufficient: 'Proof-of-work was insufficient',
        pow_replayed: 'Proof-of-work was already used',
        too_large: 'Content is larger than the server allows',
        capacity_full: 'The server is at capacity. Try again later.',
        bad_envelope: 'The link is corrupted',
        bad_key: 'Wrong key or password. The link may be incorrect.',
        network: 'Network error',
        internal: 'Server error'
    },
    units: {
        second_one: 'second',  second_few: 'seconds', second_many: 'seconds',
        minute_one: 'minute',  minute_few: 'minutes', minute_many: 'minutes',
        hour_one:   'hour',    hour_few:   'hours',   hour_many:   'hours',
        day_one:    'day',     day_few:    'days',    day_many:    'days'
    }
};
