<script>
  import { Link } from "svelte-routing";
</script>

<nav class="bg-gray-50 flex-initial md:w-64 border-r-2 border-gray-100 p-10">
    <ul>
        <li class="py-2 hover:font-bold transition-all hover:primary">
            <Link to="/">Accueil</Link>
        </li>
        <li class="py-2 hover:font-bold transition-all">
            <Link to="users">Utilisateurs</Link>
        </li>
        <li class="py-2 hover:font-bold transition-all">
            <Link to="logout">Déconnexion</Link>
        </li>
    </ul>
</nav>
