<script>
  import { Link } from "svelte-routing";
</script>

<nav class="bg-gray-50 flex-initial md:w-64 border-r-2 border-gray-100 p-10">
    <ul>
        <li>
            <Link to="/">Accueil</Link>
        </li>
        <li>
            <Link to="users">Utilisateurs</Link>
        </li>
    </ul>
</nav>
