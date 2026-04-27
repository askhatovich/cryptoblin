<script>
    import { onMount, onDestroy } from 'svelte';
    import Create from './components/Create.svelte';
    import View from './components/View.svelte';
    import Delete from './components/Delete.svelte';
    import Footer from './components/Footer.svelte';
    import { t, lang } from './lib/i18n.js';
    import { storage } from './lib/storage.js';
    import { parseLocation, navigateHome } from './lib/urlfrag.js';
    import { ready as cryptoReady } from './lib/crypto.js';
    import { api } from './lib/api.js';

    let route = $state(parseLocation());
    let cryptoLoaded = $state(false);
    let serverConfig = $state(null);
    let title = $state('CryptoBlin');
    // Bumped on every navigation to home so the Create component remounts
    // with a fresh form even when we are already on the create route (e.g.
    // clicking the brand from the post-create result card).
    let homeNav = $state(0);

    onMount(async () => {
        const theme = storage.getTheme();
        document.documentElement.classList.toggle('light', theme === 'light');
        document.title = title;

        await cryptoReady();
        cryptoLoaded = true;

        try {
            serverConfig = await api.getConfig();
            if (serverConfig.title) {
                title = serverConfig.title;
                document.title = title;
            }
        } catch { /* keep defaults */ }

        const reroute = () => {
            const next = parseLocation();
            if (next.route === 'create' && route.route !== 'create') homeNav++;
            route = next;
        };
        window.addEventListener('hashchange', reroute);
        window.addEventListener('popstate', reroute);
        return () => {
            window.removeEventListener('hashchange', reroute);
            window.removeEventListener('popstate', reroute);
        };
    });

    function goHome(e) {
        e.preventDefault();
        navigateHome();
        homeNav++;
        route = parseLocation();
    }

    function changeLang(e) {
        lang.set(e.target.value);
    }
    function toggleTheme() {
        const cur = document.documentElement.classList.contains('light') ? 'light' : 'dark';
        const next = cur === 'light' ? 'dark' : 'light';
        document.documentElement.classList.toggle('light', next === 'light');
        storage.setTheme(next);
    }
</script>

<div class="app-shell" class:wide={route.route === 'view'}>
    <header class="brand">
        <h1>
            <a class="brand-link" href="/" onclick={goHome}>
                {title}
            </a>
        </h1>
        <div class="nav">
            <button class="ghost" type="button" onclick={toggleTheme} aria-label="theme" style="padding: 4px 8px; font-size: 12px;">◑</button>
            <select class="lang" value={$lang} onchange={changeLang}>
                <option value="en">EN</option>
                <option value="ru">RU</option>
                <option value="de">DE</option>
                <option value="es">ES</option>
            </select>
        </div>
    </header>

    {#if !cryptoLoaded}
        <div class="dim">{$t('view.loading')}</div>
    {:else if route.route === 'view'}
        {#key route.id + ':' + route.seed + ':' + (route.hasPassword ? '1' : '0')}
            <View id={route.id} seed={route.seed} hasPassword={route.hasPassword} />
        {/key}
    {:else if route.route === 'delete'}
        {#key route.id + ':' + route.token}
            <Delete id={route.id} token={route.token} />
        {/key}
    {:else}
        {#key homeNav}
            <Create serverConfig={serverConfig} />
        {/key}
    {/if}

    <Footer />
</div>
