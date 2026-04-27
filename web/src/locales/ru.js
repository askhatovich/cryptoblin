export const ru = {
    app: {
        title: 'CryptoBlin',
        subtitle: 'Zero-knowledge запись: содержимое шифруется в браузере прежде чем попасть на сервер',
        privacy_blurb: 'Сквозное шифрование XChaCha20-Poly1305 с производным ключом Argon2id. Ключ генерируется в браузере отправителя и передаётся в якоре URL, который никогда не отправляется на сервер. На сервере хранится только шифротекст; прочитать содержимое записи сервер не может.'
    },
    nav: {
        new_paste: 'Новая запись',
        github: 'Исходники'
    },
    create: {
        format: 'Формат',
        format_text: 'Обычный текст',
        format_markdown: 'Markdown',
        format_code: 'Исходный код',
        language: 'Язык',
        body_placeholder: 'Вставьте или введите содержимое…',
        attach_file: 'Прикрепить файл — перетащите сюда или нажмите',
        remove_file: 'Убрать',
        burn: 'Удалить после первого прочтения',
        burn_hint: 'Запись уничтожается в момент первого открытия',
        password: 'Пароль',
        password_placeholder: 'необязательно',
        password_hint: 'Поставьте пароль, если ссылка пойдёт по менее доверенному каналу. Пароль никогда не уходит на сервер.',
        submit: 'Создать запись',
        submitting: 'Загружаем…',
        phase_captcha: 'Запрашиваем proof-of-work…',
        phase_pow: 'Решаем капчу ({tries})…',
        phase_encrypting: 'Шифруем…',
        ttl_estimate: 'Ожидаемое время жизни: {duration}',
        size_used: '{size} из {limit}',
        too_large: 'Содержимое слишком большое. Максимум {limit}.'
    },
    result: {
        title: 'Запись создана',
        copy: 'Скопировать ссылку',
        copied: 'Ссылка скопирована',
        copy_failed: 'Не удалось скопировать',
        qr: 'Показать QR-код',
        qr_title: 'Отсканируйте чтобы открыть',
        qr_close: 'Закрыть',
        new: 'Создать новую запись',
        ttl_remaining: 'Самоуничтожение через {duration}',
        burn_warning: 'Запись удалится при первом открытии',
        password_set: 'Для открытия записи требуется пароль',
        delete: 'Удалить'
    },
    delete: {
        working: 'Удаляем запись…',
        ok: 'Запись удалена',
        fail: 'Не удалось удалить запись'
    },
    view: {
        loading: 'Расшифровываем…',
        password_required: 'Запись защищена паролем',
        password_input: 'Пароль',
        password_submit: 'Открыть',
        password_wrong: 'Неверный пароль',
        burn_warning_title: 'Сжечь после прочтения',
        burn_warning_body: 'Эта запись уничтожится в момент открытия. Сохраните всю нужную информацию, после перезагрузки страницы данные уже будут недоступны.',
        burn_continue: 'Открыть и уничтожить',
        burn_cancel: 'Отмена',
        download_file: 'Скачать файл',
        copy_text: 'Скопировать текст',
        copied: 'Скопировано',
        copy_failed: 'Не удалось скопировать',
        save_text_as_file: 'Сохранить текст файлом',
        show_raw: 'Показать исходный текст',
        create_copy: 'Создать копию',
        meta_size: 'Размер',
        meta_created: 'Создано',
        meta_expires: 'Удалится через',
        meta_views: 'Просмотров',
        loading_meta: 'Загрузка…'
    },
    errors: {
        not_found: 'Запись не существует или истёк её срок',
        rate_limited: 'Слишком частые запросы капчи. Подождите немного.',
        pow_required: 'Не выполнен proof-of-work',
        pow_invalid: 'Подпись proof-of-work некорректна',
        pow_expired: 'Captcha истекла — повторите',
        pow_insufficient: 'Proof-of-work недостаточно сложный',
        pow_replayed: 'Captcha уже использована',
        too_large: 'Размер превышает допустимый',
        capacity_full: 'Сервер переполнен. Попробуйте позже.',
        bad_envelope: 'Ссылка повреждена',
        bad_key: 'Неверный ключ или пароль. Возможно, ссылка некорректная.',
        network: 'Сетевая ошибка',
        internal: 'Ошибка сервера'
    },
    units: {
        second_one: 'секунда', second_few: 'секунды', second_many: 'секунд',
        minute_one: 'минута',  minute_few: 'минуты',  minute_many: 'минут',
        hour_one:   'час',     hour_few:   'часа',    hour_many:   'часов',
        day_one:    'день',    day_few:    'дня',     day_many:    'дней'
    }
};
