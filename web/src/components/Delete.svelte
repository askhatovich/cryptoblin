<script>
    import { onMount } from 'svelte';
    import { t } from '../lib/i18n.js';
    import { api } from '../lib/api.js';

    let { id, token } = $props();

    let phase = $state('working');   // 'working' | 'ok' | 'fail'

    onMount(async () => {
        try {
            await api.deletePaste(id, token);
            phase = 'ok';
        } catch {
            phase = 'fail';
        }
    });
</script>

<div class="card">
    {#if phase === 'working'}
        <div class="dim">{$t('delete.working')}</div>
    {:else if phase === 'ok'}
        <h2 class="card-title">{$t('delete.ok')}</h2>
    {:else}
        <h2 class="card-title">{$t('delete.fail')}</h2>
    {/if}
</div>
