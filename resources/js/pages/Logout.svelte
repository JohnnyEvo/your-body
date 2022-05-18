<script>
  import {auth} from '../firebase.js';
  import {user} from '../store';

  const handleLogOut = () => {
    auth.signOut().then(function() {
      user.set({...$user, loggedIn: false});
    }, function(error) {
      console.warn('error on logout', error.message);
    });
  };
</script>

<div>
    <button on:click={handleLogOut}>Se déconnecter</button>
</div>
