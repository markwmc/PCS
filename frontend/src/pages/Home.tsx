import { IonButton, IonContent, IonHeader, IonInput, IonItem, IonLabel, IonPage, IonTitle, IonToolbar } from '@ionic/react';

import './Home.css';
import { useState } from 'react';

const Home: React.FC = () => {

    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [token, setToken] = useState<string | null>(null);
    const [data, setData] = useState<any>(null);
  
    const handleLogin = async() => {
      const response = await fetch("https://refactored-fiesta-465v4w7vpr62jvqr-8100.app.github.dev/login", {
        method: 'POST',
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          username: username,
          password: password
        }),
      });
      const data = await response.json();
      const token = data.token
      setToken(token);
      localStorage.setItem('token', token)
    }

    const fetchData = async () => {
      const token = localStorage.getItem('token')

      if (!token) {
        alert("No token found. please log in")
        return
      }

      const response = await fetch("http://localhost:8080/protected",
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        if (!response.ok) {
          alert(
            "access denied."
          )
          return;
        }
        const data = await response.json();
        setData(data);
    }
  return (
    <IonPage>
      <IonHeader>
        <IonToolbar>
          <IonTitle>Login</IonTitle>
        </IonToolbar>
      </IonHeader>
      <IonContent fullscreen>
        <IonItem>
          <IonLabel>Username</IonLabel>
          <IonInput value={username} onIonChange={(e) => setUsername(e.detail.value!)} />
            
        </IonItem>
        <IonItem>
          <IonLabel>Password</IonLabel>
          <IonInput value={password} onIonChange={(e) => setPassword(e.detail.value!)} />
        </IonItem>
        <IonButton onClick={handleLogin}>Login</IonButton>
        {token && (
          <IonButton onClick={fetchData}>Fetch Protected Data</IonButton>
        )}

        {data && (
          <div>
            <h2>Protected data</h2>
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </div>
        )}
        
      </IonContent>
    </IonPage>
  );
};

export default Home;
