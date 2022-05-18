<script>
  import {auth, provider} from '../firebase.js';
  import {signInWithPopup} from 'firebase/auth';
  import {navigate} from 'svelte-routing';
  import { user as userStore} from '../store'

  const handleGoogleLogin = () => {
    signInWithPopup(auth, provider).then((result) => {
      const user = result.user;

      if (user) {
        let {email, accessToken} = user;
        userStore.set({loggedIn: true, email, accessToken});
        navigate('/dashboard');
      }
    });
  };
</script>

<div class="flex items-center mx-auto">
    <button class="bg-primary text-white px-4 py-2 rounded-md font-bold" on:click={handleGoogleLogin}>Connexion</button>
</div>
