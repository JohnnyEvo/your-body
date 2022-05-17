<script>
  import { Router, Route } from "svelte-routing";
  import Navigation from "./components/Navigation.svelte";
  import Users from "./pages/Users.svelte";
  import Home from "./pages/Home.svelte";

  export let url = "";
</script>

<div class="container mx-auto flex flex-nowrap flex-col min-h-screen">
    <header class="bg-secondary p-6 sticky top-0 shadow">
        <h1 class="text-4xl">Slim</h1>
    </header>
    <main class="flex flex-col md:flex-row grow">
        <Router url="{url}">
            <Navigation />
            <article class="w-full bg-gray-50 p-10">
                    <Route path="users" component="{Users}" />
                    <Route path="users" component="{Home}" />
            </article>
        </Router>
    </main>
</div>
