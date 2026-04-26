export const es = {
    app: {
        title: 'CryptoBlin',
        subtitle: 'Compartir notas con conocimiento cero: el contenido se cifra en el navegador antes de llegar al servidor',
        privacy_blurb: 'Cifrado de extremo a extremo XChaCha20-Poly1305 con derivación de clave Argon2id. La clave se genera en el navegador del remitente y viaja en el fragmento de la URL, que nunca se envía al servidor. El servidor solo almacena texto cifrado y no puede leer el contenido de la nota.'
    },
    nav: {
        new_paste: 'Nueva nota',
        github: 'Código'
    },
    create: {
        format: 'Formato',
        format_text: 'Texto plano',
        format_markdown: 'Markdown',
        format_code: 'Código fuente',
        language: 'Lenguaje',
        body_placeholder: 'Escribe o pega el contenido aquí…',
        attach_file: 'Adjuntar archivo — arrástralo aquí o haz clic',
        remove_file: 'Quitar',
        burn: 'Eliminar tras la primera lectura',
        burn_hint: 'La nota se destruye en el momento en que alguien la abre',
        password: 'Contraseña',
        password_placeholder: 'opcional',
        password_hint: 'Pon una contraseña si vas a compartir el enlace por un canal poco confiable. La contraseña nunca llega al servidor.',
        submit: 'Crear nota',
        submitting: 'Subiendo…',
        phase_captcha: 'Solicitando proof-of-work…',
        phase_pow: 'Resolviendo captcha ({tries})…',
        phase_encrypting: 'Cifrando…',
        ttl_estimate: 'Vida útil estimada: {duration}',
        size_used: '{size} de {limit}',
        too_large: 'El contenido es demasiado grande. El máximo es {limit}.'
    },
    result: {
        title: 'Nota creada',
        copy: 'Copiar enlace',
        copied: 'Enlace copiado',
        copy_failed: 'No se pudo copiar',
        qr: 'Mostrar código QR',
        qr_title: 'Escanea para abrir',
        qr_close: 'Cerrar',
        new: 'Crear nueva nota',
        ttl_remaining: 'Se autodestruye en {duration}',
        burn_warning: 'Esta nota se elimina la primera vez que se abre',
        password_set: 'Se necesita una contraseña para abrir esta nota',
        delete: 'Eliminar'
    },
    delete: {
        working: 'Eliminando la nota…',
        ok: 'Nota eliminada',
        fail: 'No se pudo eliminar la nota'
    },
    view: {
        loading: 'Descifrando…',
        password_required: 'Esta nota está protegida por contraseña',
        password_input: 'Contraseña',
        password_submit: 'Abrir',
        password_wrong: 'Contraseña incorrecta',
        burn_warning_title: 'Destruir tras leer',
        burn_warning_body: 'Esta nota se destruye en el momento en que la abres. Guarda toda la información que necesites ahora — tras recargar la página los datos ya no estarán disponibles.',
        burn_continue: 'Abrir y destruir',
        burn_cancel: 'Cancelar',
        download_file: 'Descargar archivo',
        copy_text: 'Copiar texto',
        copied: 'Copiado',
        copy_failed: 'No se pudo copiar',
        save_text_as_file: 'Guardar texto como archivo',
        show_raw: 'Mostrar texto en bruto',
        create_copy: 'Crear copia',
        meta_size: 'Tamaño',
        meta_created: 'Creada',
        meta_expires: 'Expira en',
        meta_views: 'Vistas',
        loading_meta: 'Cargando…'
    },
    errors: {
        not_found: 'Esta nota no existe o ha caducado',
        rate_limited: 'Demasiadas solicitudes de captcha. Inténtalo en un momento.',
        pow_required: 'Falta el proof-of-work',
        pow_invalid: 'La firma del proof-of-work no es válida',
        pow_expired: 'Proof-of-work caducado — inténtalo de nuevo',
        pow_insufficient: 'El proof-of-work fue insuficiente',
        pow_replayed: 'El proof-of-work ya se utilizó',
        too_large: 'El contenido supera lo permitido por el servidor',
        capacity_full: 'El servidor está al límite. Inténtalo más tarde.',
        bad_envelope: 'El enlace está dañado',
        bad_key: 'Clave o contraseña incorrecta. El enlace puede ser inválido.',
        network: 'Error de red',
        internal: 'Error del servidor'
    },
    units: {
        second_one: 'segundo', second_few: 'segundos', second_many: 'segundos',
        minute_one: 'minuto',  minute_few: 'minutos',  minute_many: 'minutos',
        hour_one:   'hora',    hour_few:   'horas',    hour_many:   'horas',
        day_one:    'día',     day_few:    'días',     day_many:    'días'
    }
};
