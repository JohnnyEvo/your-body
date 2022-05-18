<script>
  import {Route, Router} from 'svelte-routing';
  import {user} from './store.js';

  import Navigation from './components/Navigation.svelte';
  import Users from './pages/Users.svelte';
  import Home from './pages/Home.svelte';
  import Login from './pages/Login.svelte';
  import Logout from './pages/Logout.svelte';


  export let url = '';
</script>

<div class="container mx-auto flex flex-nowrap flex-col min-h-screen">
    <header class="bg-secondary p-6 sticky top-0 shadow">
        <h1 class="text-4xl">Slim</h1>
    </header>
    <main class="flex flex-col md:flex-row grow">

        {#if $user.loggedIn}
            <Router url="{url}">
                <Navigation/>
                <article class="w-full bg-gray-50 p-10">
                    <Route path="users" component="{Users}"/>
                    <Route path="logout" component="{Logout}"/>
                    <Route path="" component="{Home}"/>
                </article>
            </Router>
        {:else}
            <Login />
        {/if}
    </main>
</div>
