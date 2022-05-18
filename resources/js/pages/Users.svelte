<script>
  import {user} from '../store'

  let users = [];

  $: count = users.length;

  fetch('/api/users', {
    headers: {
      Authorization: `Bearer ${$user.accessToken}`
    }
  }).then(response => response.json()).then(usersFetch => users = usersFetch);
</script>

<div>
    <div class="flex items-center">
        <h2 class="text-primary text-4xl grow">Utilisateurs</h2>

        <aside>
            {#if count > 0}
                Nombre d'utilisateur : { count }
            {:else}
                Aucun utilisateur
            {/if}
        </aside>
    </div>
    <hr class="mt-1">
</div>
