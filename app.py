import streamlit as st
import sqlite3
import time
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth

# from streamlit_authenticator.utilities import *
import hashlib
from datetime import datetime, timedelta
from datetime import datetime, date
import streamlit.components.v1 as components

# Configurazione password statica per la registrazione (default)
DEFAULT_REGISTRATION_PASSWORD = "MioGestionale2024!"


class AuthSystem:
    def __init__(self, db_path="users.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Inizializza il database e crea la tabella users se non esiste"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                nome TEXT NOT NULL,
                cognome TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """
        )

        # Nuova tabella per le impostazioni di sistema con password hashata
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS system_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_by TEXT
            )
        """
        )

        # Inserisce la password di registrazione di default hashata se non esiste
        cursor.execute(
            """
            INSERT OR IGNORE INTO system_settings (setting_key, setting_value, updated_by)
            VALUES ('registration_password_hash', ?, 'system')
        """,
            (self.hash_password(DEFAULT_REGISTRATION_PASSWORD),),
        )

        conn.commit()
        conn.close()

    def hash_password(self, password):
        """Crea un hash sicuro della password"""
        return hashlib.sha256(password.encode()).hexdigest()

    def create_user(self, username, nome, cognome, password):
        """Crea un nuovo utente nel database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            password_hash = self.hash_password(password)

            cursor.execute(
                """
                INSERT INTO users (username, nome, cognome, password_hash)
                VALUES (?, ?, ?, ?)
            """,
                (username, nome, cognome, password_hash),
            )

            conn.commit()
            conn.close()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        """Verifica le credenziali dell'utente"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        password_hash = self.hash_password(password)

        cursor.execute(
            """
            SELECT username, nome, cognome FROM users 
            WHERE username = ? AND password_hash = ?
        """,
            (username, password_hash),
        )

        user = cursor.fetchone()
        conn.close()

        if user:
            return {"username": user[0], "nome": user[1], "cognome": user[2]}
        return None

    def update_last_login(self, username):
        """Aggiorna il timestamp dell'ultimo accesso"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users SET last_login = CURRENT_TIMESTAMP 
            WHERE username = ?
        """,
            (username,),
        )

        conn.commit()
        conn.close()

    def create_session(self, username):
        """Crea una sessione per l'utente"""
        import secrets

        session_token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(days=30)  # La sessione dura 30 giorni

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Rimuovi sessioni scadute
        cursor.execute(
            "DELETE FROM user_sessions WHERE expires_at < ?", (datetime.now(),)
        )

        # Crea nuova sessione
        cursor.execute(
            """
            INSERT INTO user_sessions (username, session_token, expires_at)
            VALUES (?, ?, ?)
        """,
            (username, session_token, expires_at),
        )

        conn.commit()
        conn.close()

        return session_token

    def verify_session(self, session_token):
        """Verifica se la sessione è valida"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT u.username, u.nome, u.cognome 
            FROM user_sessions s
            JOIN users u ON s.username = u.username
            WHERE s.session_token = ? AND s.expires_at > ?
        """,
            (session_token, datetime.now()),
        )

        user = cursor.fetchone()
        conn.close()

        if user:
            return {"username": user[0], "nome": user[1], "cognome": user[2]}
        return None

    def logout_user(self, session_token):
        """Rimuove la sessione dell'utente (logout)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "DELETE FROM user_sessions WHERE session_token = ?", (session_token,)
        )

        conn.commit()
        conn.close()

    def verify_registration_password(self, password):
        """Verifica se la password di registrazione è corretta"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT setting_value FROM system_settings 
            WHERE setting_key = 'registration_password_hash'
        """
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash = result[0]
            return stored_hash == self.hash_password(password)
        else:
            # Fallback alla password di default se non trovata
            return self.hash_password(password) == self.hash_password(
                DEFAULT_REGISTRATION_PASSWORD
            )

    def update_registration_password(self, new_password, updated_by):
        """Aggiorna la password di registrazione (salvandola hashata)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            new_password_hash = self.hash_password(new_password)

            # Prima controlla se esiste già il record
            cursor.execute(
                """
                SELECT id FROM system_settings 
                WHERE setting_key = 'registration_password_hash'
            """
            )

            if cursor.fetchone():
                # Aggiorna il record esistente
                cursor.execute(
                    """
                    UPDATE system_settings 
                    SET setting_value = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
                    WHERE setting_key = 'registration_password_hash'
                """,
                    (new_password_hash, updated_by),
                )
            else:
                # Inserisce un nuovo record se non esiste
                cursor.execute(
                    """
                    INSERT INTO system_settings (setting_key, setting_value, updated_by)
                    VALUES ('registration_password_hash', ?, ?)
                """,
                    (new_password_hash, updated_by),
                )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Errore nell'aggiornamento della password di registrazione: {e}")
            return False

    def get_registration_password_info(self):
        """Ottiene informazioni sulla password di registrazione (senza restituire la password)"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT updated_at, updated_by FROM system_settings 
            WHERE setting_key = 'registration_password_hash'
        """
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {"updated_at": result[0], "updated_by": result[1], "exists": True}
        return {"exists": False}

    def get_system_setting(self, setting_key):
        """Ottiene una specifica impostazione di sistema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT setting_value, updated_at, updated_by FROM system_settings 
            WHERE setting_key = ?
        """,
            (setting_key,),
        )

        result = cursor.fetchone()
        conn.close()

        if result:
            return {
                "value": result[0],
                "updated_at": result[1],
                "updated_by": result[2],
            }
        return None


def set_cookie(name, value, days=30):
    """Imposta un cookie nel browser"""
    expires = datetime.now() + timedelta(days=days)
    expires_str = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")

    components.html(
        f"""
    <script>
        document.cookie = "{name}={value}; expires={expires_str}; path=/; SameSite=Lax";
    </script>
    """,
        height=0,
    )


def get_cookie(name):
    """Legge un cookie dal browser"""
    cookie_string = components.html(
        f"""
    <script>
        function getCookie(name) {{
            let cookieValue = null;
            if (document.cookie && document.cookie !== '') {{
                const cookies = document.cookie.split(';');
                for (let i = 0; i < cookies.length; i++) {{
                    const cookie = cookies[i].trim();
                    if (cookie.substring(0, name.length + 1) === (name + '=')) {{
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }}
                }}
            }}
            return cookieValue;
        }}
        
        const token = getCookie('{name}');
        if (token) {{
            window.parent.postMessage({{type: 'cookie', name: '{name}', value: token}}, '*');
        }}
    </script>
    """,
        height=0,
    )

    return None


def delete_cookie(name):
    """Elimina un cookie dal browser"""
    components.html(
        f"""
    <script>
        document.cookie = "{name}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";
    </script>
    """,
        height=0,
    )


def main():

    # Inizializza il sistema di autenticazione
    auth = AuthSystem()

    # Inizializza le variabili di sessione
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "user_data" not in st.session_state:
        st.session_state.user_data = None
    if "session_token" not in st.session_state:
        st.session_state.session_token = None
    if "cookie_checked" not in st.session_state:
        st.session_state.cookie_checked = False

    # Verifica la sessione salvata solo una volta per evitare loop
    if not st.session_state.logged_in and not st.session_state.cookie_checked:
        st.session_state.cookie_checked = True

        # Prova a recuperare il token dai query parameters (workaround per i cookie)
        query_params = st.query_params
        if "session_token" in query_params:
            token = query_params["session_token"]
            user_data = auth.verify_session(token)
            if user_data:
                st.session_state.logged_in = True
                st.session_state.user_data = user_data
                st.session_state.session_token = token
                # Rimuovi il token dall'URL per sicurezza
                st.query_params.clear()
                st.rerun()

    # Se l'utente è loggato, mostra il dashboard
    if st.session_state.logged_in:
        show_dashboard(auth)
    else:
        show_auth_page(auth)


def show_auth_page(auth):
    """Mostra la pagina di autenticazione (login/register)"""
    st.title("🔐 Sistema di Autenticazione")

    tab1, tab2 = st.tabs(["Accedi", "Registrati"])

    with tab1:
        st.header("Accesso")

        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            remember_me = st.checkbox("Ricordami per i prossimi accessi")

            submit_login = st.form_submit_button("Accedi")

            if submit_login:
                if username and password:
                    user_data = auth.verify_user(username, password)
                    if user_data:
                        st.session_state.logged_in = True
                        st.session_state.user_data = user_data

                        # Aggiorna ultimo accesso
                        auth.update_last_login(username)

                        # Se "ricordami" è selezionato, crea una sessione
                        if remember_me:
                            session_token = auth.create_session(username)
                            st.session_state.session_token = session_token
                            # Salva il token nell'URL per persistenza
                            st.query_params["session_token"] = session_token

                        st.success(
                            f"Benvenuto, {user_data['nome']} {user_data['cognome']}!"
                        )
                        st.rerun()
                    else:
                        st.error("Username o password non corretti!")
                else:
                    st.error("Inserisci username e password!")

    with tab2:
        st.header("Registrazione")
        st.info("⚠️ È richiesta una password speciale per registrarsi")

        with st.form("register_form"):
            reg_password_access = st.text_input(
                "Password di accesso alla registrazione", type="password"
            )

            st.divider()

            reg_username = st.text_input("Username")
            reg_nome = st.text_input("Nome")
            reg_cognome = st.text_input("Cognome")
            reg_password = st.text_input("Password", type="password")
            reg_password_confirm = st.text_input("Conferma Password", type="password")

            submit_register = st.form_submit_button("Registrati")

            if submit_register:
                # Verifica password di accesso alla registrazione usando il nuovo metodo
                if not auth.verify_registration_password(reg_password_access):
                    st.error("Password di accesso alla registrazione non corretta!")
                elif not all(
                    [
                        reg_username,
                        reg_nome,
                        reg_cognome,
                        reg_password,
                        reg_password_confirm,
                    ]
                ):
                    st.error("Compila tutti i campi!")
                elif reg_password != reg_password_confirm:
                    st.error("Le password non coincidono!")
                elif len(reg_password) < 6:
                    st.error("La password deve essere di almeno 6 caratteri!")
                else:
                    if auth.create_user(
                        reg_username, reg_nome, reg_cognome, reg_password
                    ):
                        st.success(
                            "Registrazione completata con successo! Ora puoi accedere."
                        )
                    else:
                        st.error("Username già esistente! Scegli un altro username.")


def show_dashboard(auth):
    # Tutto il codice esistente del dashboard rimane uguale...
    # [Il resto del codice rimane identico fino alla gestione delle pagine]

    # Aggiungi questa nuova pagina nelle impostazioni
    if st.session_state.current_page == "settings":
        show_settings_page(auth)


def show_settings_page(auth):
    """Mostra la pagina delle impostazioni"""
    st.markdown("## ⚙️ Impostazioni Sistema")

    st.markdown("### 🔐 Gestione Password di Registrazione")

    # Informazioni sulla password attuale
    password_info = auth.get_registration_password_info()

    if password_info["exists"]:
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Ultimo aggiornamento:** {password_info['updated_at']}")
        with col2:
            st.info(f"**Aggiornata da:** {password_info['updated_by']}")
    else:
        st.warning(
            "Password di registrazione non trovata nel database. Verrà usata quella di default."
        )

    st.divider()

    # Form per cambiare la password di registrazione
    with st.form("change_registration_password"):
        st.markdown("#### Cambia Password di Registrazione")

        current_password = st.text_input(
            "Password di registrazione attuale",
            type="password",
            help="Inserisci la password di registrazione attualmente in uso",
        )

        new_password = st.text_input(
            "Nuova password di registrazione",
            type="password",
            help="Inserisci la nuova password che gli utenti dovranno usare per registrarsi",
        )

        confirm_new_password = st.text_input(
            "Conferma nuova password",
            type="password",
            help="Ripeti la nuova password per conferma",
        )

        submit_change = st.form_submit_button(
            "🔄 Aggiorna Password", use_container_width=True
        )

        if submit_change:
            # Validazioni
            if not all([current_password, new_password, confirm_new_password]):
                st.error("❌ Compila tutti i campi!")
            elif not auth.verify_registration_password(current_password):
                st.error("❌ La password attuale non è corretta!")
            elif new_password != confirm_new_password:
                st.error("❌ Le nuove password non coincidono!")
            elif len(new_password) < 8:
                st.error("❌ La nuova password deve essere di almeno 8 caratteri!")
            elif new_password == current_password:
                st.warning("⚠️ La nuova password è uguale a quella attuale!")
            else:
                # Aggiorna la password
                if auth.update_registration_password(
                    new_password, st.session_state.user_data["username"]
                ):
                    st.success("✅ Password di registrazione aggiornata con successo!")
                    st.balloons()

                    # Mostra le nuove informazioni
                    new_info = auth.get_registration_password_info()
                    st.info(
                        f"🕒 Aggiornata il: {new_info['updated_at']} da {new_info['updated_by']}"
                    )

                    # Ricarica la pagina dopo 2 secondi
                    time.sleep(2)
                    st.rerun()
                else:
                    st.error("❌ Errore durante l'aggiornamento della password!")

    st.divider()

    # Sezione informazioni di sicurezza
    with st.expander("🔒 Informazioni sulla Sicurezza"):
        st.markdown(
            """
        **Come funziona la sicurezza delle password:**
        
        - ✅ Tutte le password sono salvate nel database utilizzando hash SHA-256
        - ✅ Le password originali non vengono mai memorizzate in chiaro
        - ✅ Solo chi conosce la password di registrazione può creare nuovi account
        - ✅ La password di registrazione può essere cambiata solo dagli utenti autenticati
        - ✅ Ogni modifica viene tracciata con data e utente che l'ha effettuata
        
        **Raccomandazioni:**
        - Usa password lunghe e complesse (almeno 8 caratteri)
        - Include lettere maiuscole, minuscole, numeri e simboli
        - Non condividere la password di registrazione con persone non autorizzate
        - Cambia periodicamente la password di registrazione
        """
        )


def show_dashboard(auth):

    # Configurazione pagina
    st.set_page_config(page_title="Lanterna Gest..", page_icon="🏖️", layout="wide")

    # File di configurazione e database

    DATABASE_FILE = "lanterna.db"

    # Funzioni per gestire il database SQLite
    def init_database():
        """Inizializza il database SQLite con le tabelle necessarie"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Tabella per le prenotazioni
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    phone TEXT,
                    email TEXT,
                    date TEXT NOT NULL,
                    return_date TEXT,
                    ombrellone INTEGER DEFAULT 0,
                    sdraio INTEGER DEFAULT 0,
                    lettino INTEGER DEFAULT 0,
                    regista INTEGER DEFAULT 0,
                    price REAL DEFAULT 0,
                    deposit_paid BOOLEAN DEFAULT FALSE,
                    insurance BOOLEAN DEFAULT FALSE,
                    notes TEXT,
                    completed BOOLEAN DEFAULT FALSE,
                    created_at TEXT NOT NULL,
                    created_by TEXT NOT NULL
                )
            """
            )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Errore nell'inizializzazione del database: {e}")
            return False

    def load_reservations():
        """Carica tutte le prenotazioni dal database SQLite"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row  # Per accedere alle colonne per nome
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM reservations ORDER BY created_at DESC")
            rows = cursor.fetchall()

            # Converte le righe in dizionari
            reservations = []
            for row in rows:
                reservation = dict(row)
                # Converte i valori boolean da SQLite (0/1 a True/False)
                reservation["deposit_paid"] = bool(reservation["deposit_paid"])
                reservation["insurance"] = bool(reservation["insurance"])
                reservation["completed"] = bool(reservation["completed"])
                reservations.append(reservation)

            conn.close()
            return reservations
        except Exception as e:
            st.error(f"Errore nel caricamento delle prenotazioni: {e}")
            return []

    def save_reservation(reservation_data):
        """Salva una nuova prenotazione nel database"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO reservations 
                (name, phone, email, date, return_date, ombrellone, sdraio, lettino, regista,
                price, deposit_paid, insurance, notes, completed, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    reservation_data["name"],
                    reservation_data["phone"],
                    reservation_data["email"],
                    reservation_data["date"],
                    reservation_data["return_date"],
                    reservation_data["ombrellone"],
                    reservation_data["sdraio"],
                    reservation_data["lettino"],
                    reservation_data["regista"],
                    reservation_data["price"],
                    reservation_data["deposit_paid"],
                    reservation_data["insurance"],
                    reservation_data["notes"],
                    reservation_data["completed"],
                    reservation_data["created_at"],
                    reservation_data["created_by"],
                ),
            )

            conn.commit()
            reservation_id = cursor.lastrowid
            conn.close()
            return reservation_id
        except Exception as e:
            st.error(f"Errore nel salvataggio della prenotazione: {e}")
            return None

    def update_reservation_status(reservation_id, completed, deposit_paid=None):
        """Aggiorna lo stato di completamento di una prenotazione"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            if deposit_paid is not None:
                cursor.execute(
                    """
                    UPDATE reservations 
                    SET completed = ?, deposit_paid = ?
                    WHERE id = ?
                """,
                    (completed, deposit_paid, reservation_id),
                )
            else:
                cursor.execute(
                    """
                    UPDATE reservations 
                    SET completed = ?
                    WHERE id = ?
                """,
                    (completed, reservation_id),
                )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Errore nell'aggiornamento della prenotazione: {e}")
            return False

    def delete_reservation(reservation_id):
        """Elimina una prenotazione dal database"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            cursor.execute("DELETE FROM reservations WHERE id = ?", (reservation_id,))

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Errore nell'eliminazione della prenotazione: {e}")
            return False

    def get_reservations_by_filter(
        date_filter=None, status_filter=None, name_filter=None, equipment_filter=None
    ):
        """Ottiene prenotazioni filtrate dal database"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM reservations WHERE 1=1"
            params = []

            if date_filter:
                query += " AND date = ?"
                params.append(str(date_filter))

            if status_filter == "Attivi":
                query += " AND completed = 0"
            elif status_filter == "Completati":
                query += " AND completed = 1"

            if name_filter:
                query += " AND LOWER(name) LIKE ?"
                params.append(f"%{name_filter.lower()}%")

            if equipment_filter and equipment_filter != "Tutte":
                equipment_map = {
                    "Ombrelloni": "ombrellone",
                    "Sdraio": "sdraio",
                    "Lettini": "lettino",
                    "Regista": "regista",
                }
                equipment_column = equipment_map[equipment_filter]
                query += f" AND {equipment_column} > 0"

            query += " ORDER BY date DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            reservations = []
            for row in rows:
                reservation = dict(row)
                reservation["deposit_paid"] = bool(reservation["deposit_paid"])
                reservation["insurance"] = bool(reservation["insurance"])
                reservation["completed"] = bool(reservation["completed"])
                reservations.append(reservation)

            conn.close()
            return reservations
        except Exception as e:
            st.error(f"Errore nel filtro delle prenotazioni: {e}")
            return []

    def export_to_json():
        """Esporta tutti i dati del database in formato JSON"""
        reservations = load_reservations()
        return reservations

    def import_from_json(json_data):
        """Importa dati JSON nel database (cancella i dati esistenti)"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()

            # Cancella tutti i dati esistenti
            cursor.execute("DELETE FROM reservations")

            # Inserisce i nuovi dati
            for reservation in json_data:
                cursor.execute(
                    """
                    INSERT INTO reservations 
                    (name, phone, email, date, return_date, ombrellone, sdraio, lettino, regista,
                    price, deposit_paid, insurance, notes, completed, created_at, created_by)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        reservation.get("name", ""),
                        reservation.get("phone", ""),
                        reservation.get("email", ""),
                        reservation.get("date", ""),
                        reservation.get("return_date", ""),
                        reservation.get("ombrellone", 0),
                        reservation.get("sdraio", 0),
                        reservation.get("lettino", 0),
                        reservation.get("regista", 0),
                        reservation.get("price", 0),
                        reservation.get("deposit_paid", False),
                        reservation.get("insurance", False),
                        reservation.get("notes", ""),
                        reservation.get("completed", False),
                        reservation.get("created_at", datetime.now().isoformat()),
                        reservation.get("created_by", "Import"),
                    ),
                )

            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Errore nell'importazione: {e}")
            return False

    def clear_all_data():
        """Cancella tutti i dati dal database"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM reservations")
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            st.error(f"Errore nella cancellazione dei dati: {e}")
            return False

    # Inizializzazione del database
    if not init_database():
        st.error("❌ Impossibile inizializzare il database")
        st.stop()

    # Inizializzazione session state
    if "reservations" not in st.session_state:
        st.session_state.reservations = load_reservations()

    if "current_page" not in st.session_state:
        st.session_state.current_page = "home"

    # Stato della pagina
    if "mode" not in st.session_state:
        st.session_state.mode = "login"

    # Funzioni per cambiare modalità e pagine
    def show_login():
        st.session_state.mode = "login"

    def show_register():
        st.session_state.mode = "register"

    def change_page(page):
        st.session_state.current_page = page

    def refresh_reservations():
        """Ricarica le prenotazioni dal database"""
        st.session_state.reservations = load_reservations()

    # CSS personalizzato (uguale a prima)
    st.markdown(
        """
    <style>
        /* Cards responsive e con effetto vetro */
        .rental-card, .completed-rental {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            color: white;
            border-radius: 15px;
            padding: 20px;
            margin: 10px 0;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            border: 1px solid rgba(255, 255, 255, 0.18);
            width: 100%;
            box-sizing: border-box;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
        }

        /* Gradiente per rental-card */
        .rental-card {
            background: linear-gradient(135deg, rgba(102, 126, 234, 0.8) 0%, rgba(118, 75, 162, 0.8) 100%);
        }

        /* Stessa dimensione e margini ma colore verde per completed-rental */
        .completed-rental {
            background: linear-gradient(135deg, rgba(76, 175, 80, 0.8) 0%, rgba(69, 160, 73, 0.8) 100%);
        }

        /* Stats cards responsive con effetto vetro */
        .stats-card {
            background: rgba(255, 255, 255, 0.8);
            backdrop-filter: blur(5px);
            -webkit-backdrop-filter: blur(5px);
            border-radius: 10px;
            padding: 15px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin: 10px 0;
            width: 100%;
            box-sizing: border-box;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        /* Equipment badge */
        .equipment-badge {
            background-color: rgba(255,255,255,0.2);
            border-radius: 20px;
            padding: 5px 12px;
            margin: 5px;
            display: inline-block;
            font-size: 0.9em;
        }

        /* Bottone stile */
        .stButton > button {
            border-radius: 10px;
            border: none;
            background: linear-gradient(45deg, #667eea, #764ba2);
            color: white;
            width: 100%;
            max-width: 200px;
            padding: 10px;
            margin: 5px 0;
        }
        
        button.st-emotion-cache-actwcs.eacrzsi2:hover {
            color: #7f7fff;
        }

        /* Media query per mobile */
        @media (max-width: 768px) {
        .rental-card, .completed-rental, .stats-card {
            padding: 7px;
            align-items: center;
            justify-content: left;
            display: flex;
        }
                
        .txt-card {
            margin: 0px !important;
        }
            
        .equipment-badge {
            font-size: 0.8em;
            padding: 4px 10px;
        }
                
        .stButton {
            display: flex;
            justify-content: center;
        }
                
        }
    </style>
    """,
        unsafe_allow_html=True,
    )

    # Sidebar e contenuto principale (solo se autenticato)
    if st.session_state.logged_in and "user_data" in st.session_state:

        # Sidebar
        with st.sidebar:
            st.markdown("### 🏖️  Gestionale Lanterna")

            # Informazioni utente
            st.info(f"👤 **Utente:** {st.session_state.user_data['username']}")

            st.divider()

            # Navigazione
            if st.button("🏠 Dashboard", use_container_width=True):
                change_page("home")
                refresh_reservations()

            if st.button("📋 Gestione Noleggi", use_container_width=True):
                change_page("rentals")
                refresh_reservations()

            if st.button("📊 Statistiche", use_container_width=True):
                change_page("stats")
                refresh_reservations()

            if st.button("👤 Profilo", use_container_width=True):
                change_page("profile")

            if st.button("⚙️ Impostazioni", use_container_width=True):
                change_page("settings")

            st.divider()

            # Logout

        # Contenuto principale basato sulla pagina corrente
        if st.session_state.current_page == "home":
            st.markdown("## 🏠 Dashboard Generale")

            # Statistiche rapide
            col1, col2 = st.columns(2)

            total_rentals = len(st.session_state.reservations)
            completed_rentals = len(
                [r for r in st.session_state.reservations if r.get("completed", False)]
            )
            active_rentals = total_rentals - completed_rentals

            # Stile CSS
            st.markdown(
                """
                <style>
                .stats-card h2, .stats-card p {
                    color: #000000 !important;
                }
                </style>
            """,
                unsafe_allow_html=True,
            )

            # Colonna 1 - Elementi in verticale
            with col1:
                st.markdown(
                    """
                <div class="stats-card">
                    <h3>📋</h3>
                    <h2>{}</h2>
                    <p class="txt-card">Noleggi Totali</p>
                </div>
                """.format(
                        total_rentals
                    ),
                    unsafe_allow_html=True,
                )

                st.markdown(
                    """
                <div class="stats-card">
                    <h3>✅</h3>
                    <h2>{}</h2>
                    <p class="txt-card">Completati</p>
                </div>
                """.format(
                        completed_rentals
                    ),
                    unsafe_allow_html=True,
                )

            # Colonna 2 - Elementi in verticale
            with col2:
                st.markdown(
                    """
                <div class="stats-card">
                    <h3>⏳</h3>
                    <h2>{}</h2>
                    <p class="txt-card">Attivi</p>
                </div>
                """.format(
                        active_rentals
                    ),
                    unsafe_allow_html=True,
                )

                today_rentals = len(
                    [
                        r
                        for r in st.session_state.reservations
                        if r.get("date") == str(date.today())
                    ]
                )
                st.markdown(
                    """
                <div class="stats-card">
                    <h3>📅</h3>
                    <h2>{}</h2>
                    <p class="txt-card">Oggi</p>
                </div>
                """.format(
                        today_rentals
                    ),
                    unsafe_allow_html=True,
                )

            st.divider()

            # Noleggi recenti
            st.markdown("### 📅 Noleggi Recenti")
            st.markdown("##### Elenco Tutti i Noleggi")
            recent_rentals = sorted(
                st.session_state.reservations,
                key=lambda x: x.get("created_at", ""),
                reverse=True,
            )[:30]

            if recent_rentals:
                for rental in recent_rentals:
                    status_class = (
                        "completed-rental"
                        if rental.get("completed", False)
                        else "rental-card"
                    )
                    status_icon = "✅" if rental.get("completed", False) else "⏳"

                    equipment_badges = ""
                    if rental.get("ombrellone", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">☂️ {rental["ombrellone"]}</span>'
                    if rental.get("sdraio", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🪑 {rental["sdraio"]}</span>'
                    if rental.get("lettino", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🛏️ {rental["lettino"]}</span>'
                    if rental.get("regista", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🎬 {rental["regista"]}</span>'

                    st.markdown(
                        f"""
                    <div class="{status_class}">
                        <h4>{status_icon} {rental['name']}</h4>
                        <p><strong>📅 Data:</strong> {rental['date']}</p>
                        <p><strong>🏖️ Kit:</strong> {equipment_badges}</p>
                        <small>👤 Creato da: {rental.get('created_by', 'N/A')}</small>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )
            else:
                st.info("🌊 Nessun noleggio presente")

        elif st.session_state.current_page == "rentals":
            st.markdown("## 📋 Gestione Noleggi")

            # Form per nuovo noleggio
            with st.expander("➕ Nuovo Noleggio", expanded=False):
                with st.form("new_rental"):
                    st.markdown("### 📝 Dettagli Cliente")
                    col1, col2 = st.columns(2)

                    with col1:
                        client_name = st.text_input(
                            "👤 Nome Cliente", placeholder="Nome e cognome"
                        )
                        rental_date = st.date_input(
                            "📅 Data Noleggio", value=date.today()
                        )
                        phone = st.text_input(
                            "📞 Telefono", placeholder="Numero di telefono"
                        )

                    with col2:
                        email = st.text_input(
                            "📧 Email", placeholder="email@esempio.com"
                        )
                        return_date = st.date_input(
                            "📅 Data Restituzione", value=date.today()
                        )
                        price = st.number_input(
                            "💰 Prezzo Totale (€)", min_value=0.0, step=0.5
                        )

                    st.divider()
                    st.markdown("### 🏖️ Kit Mare")

                    # Contatori per attrezzature
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        ombrellone = st.number_input(
                            "☂️ Ombrelloni", min_value=0, max_value=20, value=0
                        )
                    with col2:
                        sdraio = st.number_input(
                            "🪑 Sedie Sdraio", min_value=0, max_value=50, value=0
                        )
                    with col3:
                        lettino = st.number_input(
                            "🛏️ Lettini", min_value=0, max_value=30, value=0
                        )
                    with col4:
                        regista = st.number_input(
                            "🎬 Sedie Regista", min_value=0, max_value=20, value=0
                        )

                    notes = st.text_area(
                        "📝 Note Aggiuntive",
                        placeholder="Eventuali note sul noleggio...",
                    )

                    col1, col2 = st.columns(2)
                    with col1:
                        deposit_paid = st.checkbox("💳 Deposito Pagato")
                    with col2:
                        insurance = st.checkbox("🛡️ Assicurazione")

                    if st.form_submit_button(
                        "💾 Salva Noleggio", use_container_width=True
                    ):
                        if client_name.strip():
                            new_rental = {
                                "name": client_name.strip(),
                                "phone": phone,
                                "email": email,
                                "date": str(rental_date),
                                "return_date": str(return_date),
                                "ombrellone": ombrellone,
                                "sdraio": sdraio,
                                "lettino": lettino,
                                "regista": regista,
                                "price": price,
                                "deposit_paid": deposit_paid,
                                "insurance": insurance,
                                "notes": notes,
                                "completed": False,
                                "created_at": datetime.now().isoformat(),
                                "created_by": st.session_state.user_data["username"],
                            }

                            reservation_id = save_reservation(new_rental)
                            if reservation_id:
                                st.success("✅ Noleggio salvato con successo!")
                                refresh_reservations()
                                st.rerun()
                            else:
                                st.error("❌ Errore nel salvataggio")
                        else:
                            st.error("⚠️ Il nome del cliente è obbligatorio")

            st.divider()

            # Filtri
            st.markdown("### 🔍 Filtri di Ricerca")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                filter_date = st.date_input("📅 Data", value=None, key="filter_date")
            with col2:
                filter_status = st.selectbox("Stato", ["Tutti", "Attivi", "Completati"])
            with col3:
                search_name = st.text_input("🔍 Cerca nome", key="search_name")
            with col4:
                equipment_filter = st.selectbox(
                    "Attrezzatura",
                    ["Tutte", "Ombrelloni", "Sdraio", "Lettini", "Regista"],
                )

            # Applica filtri e ottieni prenotazioni filtrate
            filtered_reservations = get_reservations_by_filter(
                date_filter=filter_date,
                status_filter=filter_status if filter_status != "Tutti" else None,
                name_filter=search_name if search_name else None,
                equipment_filter=equipment_filter,
            )

            # Lista dei noleggi
            st.markdown("### 📋 Lista Noleggi")

            if filtered_reservations:
                for i, rental in enumerate(filtered_reservations):
                    status_class = (
                        "completed-rental"
                        if rental.get("completed", False)
                        else "rental-card"
                    )
                    status_icon = "✅" if rental.get("completed", False) else "⏳"

                    # Creazione badges per attrezzature
                    equipment_badges = ""
                    if rental.get("ombrellone", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">☂️ {rental["ombrellone"]}</span>'
                    if rental.get("sdraio", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🪑 {rental["sdraio"]}</span>'
                    if rental.get("lettino", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🛏️ {rental["lettino"]}</span>'
                    if rental.get("regista", 0) > 0:
                        equipment_badges += f'<span class="equipment-badge">🎬 {rental["regista"]}</span>'

                    # Card del noleggio
                    st.markdown(
                        f"""
                    <div class="{status_class}">
                        <h4>{status_icon} {rental['name']}</h4>
                        <p><strong>📅 Data:</strong> {rental['date']} - {rental.get('return_date', 'N/A')}</p>
                        <p><strong>📞 Telefono:</strong> {rental.get('phone', 'N/A')}</p>
                        <p><strong>📧 Email:</strong> {rental.get('email', 'N/A')}</p>
                        <p><strong>🏖️ Kit:</strong> {equipment_badges}</p>
                        <p><strong>💰 Prezzo:</strong> €{rental.get('price', 0):.2f}</p>
                        <p><strong>💳 Deposito:</strong> {'✅ Pagato' if rental.get('deposit_paid', False) else '❌ Non pagato'}</p>
                        <p><strong>🛡️ Assicurazione:</strong> {'✅ Attiva' if rental.get('insurance', False) else '❌ Non attiva'}</p>
                        <p><strong>📝 Note:</strong> {rental.get("notes", "❌ Nessuna nota") or "❌ Nessuna nota"}</p>
                        <small>👤 Creato da: {rental.get('created_by', 'N/A')} il {rental.get('created_at', 'N/A')[:10]}</small>
                    </div>
                    """,
                        unsafe_allow_html=True,
                    )

                    # Bottoni larghi a tutta pagina
                    col1, col2, col3 = st.columns([1, 1, 1])  # Colonne equamente divise

                    with col1:
                        if not rental.get("completed", False):
                            if st.button(
                                "✅ Completa",
                                key=f"complete_{rental['id']}",
                                use_container_width=True,
                            ):
                                if update_reservation_status(rental["id"], True):
                                    st.success("Noleggio completato!")
                                    refresh_reservations()
                                    st.rerun()
                        else:
                            if st.button(
                                "↩️ Riattiva",
                                key=f"reactivate_{rental['id']}",
                                use_container_width=True,
                            ):
                                if update_reservation_status(rental["id"], False):
                                    st.success("Noleggio riattivato!")
                                    refresh_reservations()
                                    st.rerun()

                    with col2:
                        if st.button(
                            "💳 Toggle Deposito",
                            key=f"deposit_{rental['id']}",
                            use_container_width=True,
                        ):
                            new_deposit_status = not rental.get("deposit_paid", False)
                            if update_reservation_status(
                                rental["id"],
                                rental.get("completed", False),
                                new_deposit_status,
                            ):
                                st.success(
                                    f"Deposito {'pagato' if new_deposit_status else 'non pagato'}!"
                                )
                                refresh_reservations()
                                st.rerun()

                    with col3:
                        if st.button(
                            "🗑️ Elimina",
                            key=f"delete_{rental['id']}",
                            use_container_width=True,
                        ):
                            if delete_reservation(rental["id"]):
                                st.success("Noleggio eliminato!")
                                refresh_reservations()
                                st.rerun()
                            else:
                                st.error("Errore nell'eliminazione!")

        elif st.session_state.current_page == "stats":
            st.markdown("## 📊 Statistiche")

            # Calcolo statistiche
            total_rentals = len(st.session_state.reservations)
            completed_rentals = len(
                [r for r in st.session_state.reservations if r.get("completed", False)]
            )
            active_rentals = total_rentals - completed_rentals

            # Statistiche per attrezzatura
            total_ombrelloni = sum(
                [r.get("ombrellone", 0) for r in st.session_state.reservations]
            )
            total_sdraio = sum(
                [r.get("sdraio", 0) for r in st.session_state.reservations]
            )
            total_lettini = sum(
                [r.get("lettino", 0) for r in st.session_state.reservations]
            )
            total_regista = sum(
                [r.get("regista", 0) for r in st.session_state.reservations]
            )

            # Ricavi
            total_revenue = sum(
                [r.get("price", 0) for r in st.session_state.reservations]
            )
            paid_deposits = len(
                [
                    r
                    for r in st.session_state.reservations
                    if r.get("deposit_paid", False)
                ]
            )

            # Layout statistiche
            col1, col2 = st.columns(2)

            with col1:
                st.markdown("### 📈 Statistiche Generali")
                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>📋 Noleggi Totali</h3>
                    <h2>{total_rentals}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>✅ Completati</h3>
                    <h2>{completed_rentals}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>⏳ Attivi</h3>
                    <h2>{active_rentals}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

            with col2:
                st.markdown("### 🏖️ Attrezzature Noleggiate")
                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>☂️ Ombrelloni</h3>
                    <h2>{total_ombrelloni}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>🪑 Sdraio</h3>
                    <h2>{total_sdraio}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>🛏️ Lettini</h3>
                    <h2>{total_lettini}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

            st.divider()

            # Statistiche finanziarie
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>💰 Ricavi Totali</h3>
                    <h2>€{total_revenue:.2f}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

            with col2:
                st.markdown(
                    f"""
                <div class="stats-card">
                    <h3>💳 Depositi Pagati</h3>
                    <h2>{paid_deposits}/{total_rentals}</h2>
                </div>
                """,
                    unsafe_allow_html=True,
                )

            # Grafico noleggi per data (se ci sono dati)
            if st.session_state.reservations:
                st.markdown("### 📅 Noleggi per Data")

                # Raggruppa per data
                from collections import defaultdict

                rentals_by_date = defaultdict(int)
                for rental in st.session_state.reservations:
                    rental_date = rental.get("date", "")
                    if rental_date:
                        rentals_by_date[rental_date] += 1

                if rentals_by_date:
                    dates = sorted(rentals_by_date.keys())
                    counts = [rentals_by_date[date] for date in dates]

                    # Crea DataFrame per il grafico
                    import pandas as pd

                    chart_data = pd.DataFrame({"Data": dates, "Noleggi": counts})

                    st.line_chart(chart_data.set_index("Data"))

        elif st.session_state.current_page == "profile":
            st.markdown("## 👤 Profilo Utente")

            st.info(
                f"**Nome Utente:** {st.session_state.user_data['nome']} {st.session_state.user_data['cognome']}"
            )
            st.info(f"**Username:** {st.session_state.user_data['username']}")

            st.divider()

            # Reset password registrazione

            st.markdown("### 🔐 Gestione Password di Registrazione")

            # Form per cambiare la password di registrazione
            with st.form("change_registration_password"):
                st.markdown("#### Cambia Password di Registrazione")

                current_password = st.text_input(
                    "Password di registrazione attuale",
                    type="password",
                    help="Inserisci la password di registrazione attualmente in uso",
                )

                new_password = st.text_input(
                    "Nuova password di registrazione",
                    type="password",
                    help="Inserisci la nuova password che gli utenti dovranno usare per registrarsi",
                )

                confirm_new_password = st.text_input(
                    "Conferma nuova password",
                    type="password",
                    help="Ripeti la nuova password per conferma",
                )

                submit_change = st.form_submit_button(
                    "🔄 Aggiorna Password", use_container_width=True
                )

                if submit_change:
                    # Validazioni
                    if not all([current_password, new_password, confirm_new_password]):
                        st.error("❌ Compila tutti i campi!")
                    elif not auth.verify_registration_password(current_password):
                        st.error("❌ La password attuale non è corretta!")
                    elif new_password != confirm_new_password:
                        st.error("❌ Le nuove password non coincidono!")
                    elif len(new_password) < 8:
                        st.error(
                            "❌ La nuova password deve essere di almeno 8 caratteri!"
                        )
                    elif new_password == current_password:
                        st.warning("⚠️ La nuova password è uguale a quella attuale!")
                    else:
                        # Aggiorna la password
                        if auth.update_registration_password(
                            new_password, st.session_state.user_data["username"]
                        ):
                            st.success(
                                "✅ Password di registrazione aggiornata con successo!"
                            )
                            st.balloons()

                            # Mostra le nuove informazioni
                            new_info = auth.get_registration_password_info()
                            st.info(
                                f"🕒 Aggiornata il: {new_info['updated_at']} da {new_info['updated_by']}"
                            )

                            # Ricarica la pagina dopo 2 secondi
                            time.sleep(2)
                            st.rerun()
                        else:
                            st.error(
                                "❌ Errore durante l'aggiornamento della password!"
                            )

            st.divider()
            # Informazioni sulla password attuale
            password_info = auth.get_registration_password_info()

            if password_info["exists"]:
                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"**Ultimo aggiornamento:** {password_info['updated_at']}")
                with col2:
                    st.info(f"**Aggiornata da:** {password_info['updated_by']}")
            else:
                st.warning(
                    "Password di registrazione non trovata nel database. Verrà usata quella di default."
                )

        elif st.session_state.current_page == "settings":
            st.markdown("## ⚙️ Impostazioni Sistema")

            # Backup e restore
            st.markdown("### 💾 Backup e Ripristino")

            col1, col2 = st.columns(2)

            with col1:
                st.markdown("#### 📤 Esporta Dati")
                if st.button("💾 Scarica Backup", use_container_width=True):
                    import json

                    backup_data = export_to_json()
                    backup_json = json.dumps(backup_data, indent=2, ensure_ascii=False)

                    st.download_button(
                        label="📥 Download Backup JSON",
                        data=backup_json,
                        file_name=f"cormorano_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        mime="application/json",
                        use_container_width=True,
                    )

            with col2:
                st.markdown("#### 📥 Importa Dati")
                uploaded_file = st.file_uploader("Carica file JSON", type=["json"])

                if uploaded_file and st.button(
                    "📤 Importa Backup", use_container_width=True
                ):
                    try:
                        import json

                        backup_data = json.loads(
                            uploaded_file.getvalue().decode("utf-8")
                        )

                        if import_from_json(backup_data):
                            st.success("✅ Dati importati con successo!")
                            refresh_reservations()
                            st.rerun()
                        else:
                            st.error("❌ Errore nell'importazione")
                    except Exception as e:
                        st.error(f"❌ Errore nel parsing del file: {e}")

            st.divider()

            # Gestione database
            st.markdown("### 🗃️ Gestione Database")
            st.warning("⚠️ Attenzione: Queste operazioni sono irreversibili!")

            col1, col2 = st.columns(2)

            with col1:
                if st.button("🗑️ Cancella Tutti i Dati", use_container_width=True):
                    if clear_all_data():
                        st.success("✅ Tutti i dati sono stati cancellati!")
                        refresh_reservations()
                        st.rerun()
                    else:
                        st.error("❌ Errore nella cancellazione")

            with col2:
                st.markdown("**Totale record nel database:**")
                st.info(f"📊 {len(st.session_state.reservations)} prenotazioni")

            st.divider()

            # Informazioni sistema
            st.markdown("### ℹ️ Informazioni Sistema")
            st.info(f"**Database:** {DATABASE_FILE}")
            st.info(f"**Versione App:** 1.0.0")

            # Verifica integrità database
            if st.button("🔍 Verifica Integrità Database"):
                try:
                    conn = sqlite3.connect(DATABASE_FILE)
                    cursor = conn.cursor()
                    cursor.execute("PRAGMA integrity_check")
                    result = cursor.fetchone()
                    conn.close()

                    if result[0] == "ok":
                        st.success("✅ Database integro")
                    else:
                        st.error(f"❌ Problemi nel database: {result[0]}")
                except Exception as e:
                    st.error(f"❌ Errore nella verifica: {e}")

    # Footer
    st.markdown("---")
    st.markdown(
        """
    <div style='text-align: center; color: #666; font-size: 0.8em;'>
        🏖️ Sistema Gestionale Lanterna - Sviluppato da Michele Landini<br>
        © 2024 - Gestione Noleggi Attrezzature Mare
    </div>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
