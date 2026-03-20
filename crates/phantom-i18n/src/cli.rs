//! CLI-specific texts for phantom-signer

use crate::Lang;

pub struct CliTexts {
    // Wallet Init
    pub wallet_init_title: &'static str,
    pub wallet_init_generating: &'static str,
    pub wallet_init_important: &'static str,
    pub wallet_init_write_down: &'static str,
    pub wallet_init_press_enter: &'static str,
    pub wallet_init_success: &'static str,

    // Seed Display
    pub seed_words: &'static str,

    // Seed Verification
    pub seed_verify_title: &'static str,
    pub seed_verify_hint: &'static str,
    pub seed_verify_prompt: &'static str,
    pub seed_verify_wrong: &'static str,
    pub seed_verify_correct: &'static str,
    pub seed_verify_success: &'static str,

    // Wallet Restore
    pub wallet_restore_title: &'static str,
    pub wallet_restore_enter_seed: &'static str,
    pub wallet_restore_recognized: &'static str,
    pub wallet_restore_success: &'static str,
    pub wallet_restore_invalid: &'static str,
    pub wallet_restore_wrong_count: &'static str,

    // Passphrase
    pub passphrase_enter: &'static str,
    pub passphrase_policy: &'static str,

    // Output
    pub wallet_name: &'static str,
    pub first_address: &'static str,
    pub wallet_db: &'static str,
    pub xpub_store: &'static str,
    pub seed_store: &'static str,
    pub seed_saved: &'static str,
    pub xpub_created: &'static str,
    pub wallet_initialized: &'static str,
}

pub const CLI_EN: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM WALLET INITIALIZATION",
    wallet_init_generating: "A new BIP39 seed (24 words) is being generated.",
    wallet_init_important: "IMPORTANT: Write down the 24 words on paper and store them safely!",
    wallet_init_write_down: "Without the seed, recovery is NOT possible.",
    wallet_init_press_enter: "IMPORTANT: Write down ALL 24 words on paper!\nPress ENTER when finished...",
    wallet_init_success: "WALLET SUCCESSFULLY CREATED",

    seed_words: "Your 24-word seed (BIP39 Mnemonic):",

    seed_verify_title: "SEED VERIFICATION",
    seed_verify_hint: "For security: Enter each word when prompted.\nThe order is random - pay attention to the number!",
    seed_verify_prompt: "Word #",
    seed_verify_wrong: "Wrong! Correct would be: \"{}\" - please correct in your notes.",
    seed_verify_correct: "Correct!",
    seed_verify_success: "✓ SEED SUCCESSFULLY VERIFIED",

    wallet_restore_title: "PHANTOM WALLET RESTORATION",
    wallet_restore_enter_seed: "Enter your existing BIP39 seed (24 words).",
    wallet_restore_recognized: "Seed recognized ({} words). Restoring wallet...",
    wallet_restore_success: "WALLET SUCCESSFULLY RESTORED",
    wallet_restore_invalid: "Invalid mnemonic",
    wallet_restore_wrong_count: "Mnemonic must have 24 words, got: {}",

    passphrase_enter: "Passphrase (min. 8 characters, case-sensitive, digits and special characters are distinguished): ",
    passphrase_policy: "Passphrase: min. 8 characters, case-sensitive",

    wallet_name: "Wallet Name",
    first_address: "First Address",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed saved (encrypted)",
    xpub_created: "xpubstore created",
    wallet_initialized: "walletdb initialized",
};

pub const CLI_DE: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM WALLET INITIALISIERUNG",
    wallet_init_generating: "Ein neuer BIP39-Seed (24 Wörter) wird generiert.",
    wallet_init_important: "WICHTIG: Notiere die 24 Wörter auf Papier und bewahre sie sicher auf!",
    wallet_init_write_down: "Ohne Seed ist eine Wiederherstellung NICHT möglich.",
    wallet_init_press_enter: "WICHTIG: Schreibe ALLE 24 Wörter auf Papier auf!\nDrücke ENTER wenn du fertig bist...",
    wallet_init_success: "WALLET ERFOLGREICH ERSTELLT",

    seed_words: "Dein 24-Wort-Seed (BIP39 Mnemonic):",

    seed_verify_title: "SEED-VERIFIZIERUNG",
    seed_verify_hint: "Zur Sicherheit: Gib jedes Wort ein, wenn danach gefragt wird.\nDie Reihenfolge ist zufällig - achte auf die Nummer!",
    seed_verify_prompt: "Wort #",
    seed_verify_wrong: "Falsch! Korrekt wäre: \"{}\" - bitte in deinen Notizen korrigieren.",
    seed_verify_correct: "Richtig!",
    seed_verify_success: "✓ SEED ERFOLGREICH VERIFIZIERT",

    wallet_restore_title: "PHANTOM WALLET WIEDERHERSTELLUNG",
    wallet_restore_enter_seed: "Gib deinen existierenden BIP39-Seed (24 Wörter) ein.",
    wallet_restore_recognized: "Seed erkannt ({} Wörter). Wallet wird wiederhergestellt...",
    wallet_restore_success: "WALLET ERFOLGREICH WIEDERHERGESTELLT",
    wallet_restore_invalid: "Ungültiger Mnemonic",
    wallet_restore_wrong_count: "Mnemonic muss 24 Wörter haben, bekam: {}",

    passphrase_enter: "Passphrase (mind. 8 Zeichen, Groß-/Kleinschreibung, Ziffern und Sonderzeichen werden unterschieden): ",
    passphrase_policy: "Passphrase: mind. 8 Zeichen, Groß-/Kleinschreibung beachten",

    wallet_name: "Wallet-Name",
    first_address: "Erste Adresse",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed gespeichert (verschlüsselt)",
    xpub_created: "xpubstore erstellt",
    wallet_initialized: "walletdb initialisiert",
};

pub const CLI_ES: CliTexts = CliTexts {
    wallet_init_title: "INICIALIZACIÓN DE CARTERA PHANTOM",
    wallet_init_generating: "Se está generando una nueva semilla BIP39 (24 palabras).",
    wallet_init_important: "IMPORTANTE: ¡Escribe las 24 palabras en papel y guárdalas de forma segura!",
    wallet_init_write_down: "Sin la semilla, la recuperación NO es posible.",
    wallet_init_press_enter: "IMPORTANTE: ¡Escribe TODAS las 24 palabras en papel!\nPresiona ENTER cuando termines...",
    wallet_init_success: "CARTERA CREADA EXITOSAMENTE",

    seed_words: "Tu semilla de 24 palabras (BIP39 Mnemonic):",

    seed_verify_title: "VERIFICACIÓN DE SEMILLA",
    seed_verify_hint: "Por seguridad: Ingresa cada palabra cuando se te pida.\n¡El orden es aleatorio - presta atención al número!",
    seed_verify_prompt: "Palabra #",
    seed_verify_wrong: "¡Incorrecto! Correcto sería: \"{}\" - por favor corrige en tus notas.",
    seed_verify_correct: "¡Correcto!",
    seed_verify_success: "✓ SEMILLA VERIFICADA EXITOSAMENTE",

    wallet_restore_title: "RESTAURACIÓN DE CARTERA PHANTOM",
    wallet_restore_enter_seed: "Ingresa tu semilla BIP39 existente (24 palabras).",
    wallet_restore_recognized: "Semilla reconocida ({} palabras). Restaurando cartera...",
    wallet_restore_success: "CARTERA RESTAURADA EXITOSAMENTE",
    wallet_restore_invalid: "Mnemónico inválido",
    wallet_restore_wrong_count: "El mnemónico debe tener 24 palabras, recibido: {}",

    passphrase_enter: "Contraseña (mín. 8 caracteres, distingue mayúsculas/minúsculas): ",
    passphrase_policy: "Contraseña: mín. 8 caracteres, distingue mayúsculas",

    wallet_name: "Nombre de Cartera",
    first_address: "Primera Dirección",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "semilla guardada (encriptada)",
    xpub_created: "xpubstore creado",
    wallet_initialized: "walletdb inicializado",
};

pub const CLI_FR: CliTexts = CliTexts {
    wallet_init_title: "INITIALISATION DU PORTEFEUILLE PHANTOM",
    wallet_init_generating: "Une nouvelle graine BIP39 (24 mots) est en cours de génération.",
    wallet_init_important: "IMPORTANT: Notez les 24 mots sur papier et conservez-les en sécurité!",
    wallet_init_write_down: "Sans la graine, la récupération n'est PAS possible.",
    wallet_init_press_enter: "IMPORTANT: Écrivez TOUS les 24 mots sur papier!\nAppuyez sur ENTRÉE quand c'est fait...",
    wallet_init_success: "PORTEFEUILLE CRÉÉ AVEC SUCCÈS",

    seed_words: "Votre graine de 24 mots (BIP39 Mnemonic):",

    seed_verify_title: "VÉRIFICATION DE LA GRAINE",
    seed_verify_hint: "Pour la sécurité: Entrez chaque mot quand demandé.\nL'ordre est aléatoire - faites attention au numéro!",
    seed_verify_prompt: "Mot #",
    seed_verify_wrong: "Faux! Le correct serait: \"{}\" - veuillez corriger dans vos notes.",
    seed_verify_correct: "Correct!",
    seed_verify_success: "✓ GRAINE VÉRIFIÉE AVEC SUCCÈS",

    wallet_restore_title: "RESTAURATION DU PORTEFEUILLE PHANTOM",
    wallet_restore_enter_seed: "Entrez votre graine BIP39 existante (24 mots).",
    wallet_restore_recognized: "Graine reconnue ({} mots). Restauration du portefeuille...",
    wallet_restore_success: "PORTEFEUILLE RESTAURÉ AVEC SUCCÈS",
    wallet_restore_invalid: "Mnémonique invalide",
    wallet_restore_wrong_count: "Le mnémonique doit avoir 24 mots, reçu: {}",

    passphrase_enter: "Mot de passe (min. 8 caractères, sensible à la casse): ",
    passphrase_policy: "Mot de passe: min. 8 caractères, sensible à la casse",

    wallet_name: "Nom du Portefeuille",
    first_address: "Première Adresse",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "graine sauvegardée (chiffrée)",
    xpub_created: "xpubstore créé",
    wallet_initialized: "walletdb initialisé",
};

pub const CLI_IT: CliTexts = CliTexts {
    wallet_init_title: "INIZIALIZZAZIONE PORTAFOGLIO PHANTOM",
    wallet_init_generating: "Generazione di un nuovo seed BIP39 (24 parole).",
    wallet_init_important: "IMPORTANTE: Scrivi le 24 parole su carta e conservale al sicuro!",
    wallet_init_write_down: "Senza il seed, il recupero NON è possibile.",
    wallet_init_press_enter: "IMPORTANTE: Scrivi TUTTE le 24 parole su carta!\nPremi INVIO quando hai finito...",
    wallet_init_success: "PORTAFOGLIO CREATO CON SUCCESSO",

    seed_words: "Il tuo seed di 24 parole (BIP39 Mnemonic):",

    seed_verify_title: "VERIFICA SEED",
    seed_verify_hint: "Per sicurezza: Inserisci ogni parola quando richiesto.\nL'ordine è casuale - fai attenzione al numero!",
    seed_verify_prompt: "Parola #",
    seed_verify_wrong: "Sbagliato! Corretto sarebbe: \"{}\" - correggi nelle tue note.",
    seed_verify_correct: "Corretto!",
    seed_verify_success: "✓ SEED VERIFICATO CON SUCCESSO",

    wallet_restore_title: "RIPRISTINO PORTAFOGLIO PHANTOM",
    wallet_restore_enter_seed: "Inserisci il tuo seed BIP39 esistente (24 parole).",
    wallet_restore_recognized: "Seed riconosciuto ({} parole). Ripristino portafoglio...",
    wallet_restore_success: "PORTAFOGLIO RIPRISTINATO CON SUCCESSO",
    wallet_restore_invalid: "Mnemonico non valido",
    wallet_restore_wrong_count: "Il mnemonico deve avere 24 parole, ricevuto: {}",

    passphrase_enter: "Password (min. 8 caratteri, maiuscole/minuscole): ",
    passphrase_policy: "Password: min. 8 caratteri, maiuscole/minuscole",

    wallet_name: "Nome Portafoglio",
    first_address: "Primo Indirizzo",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed salvato (crittografato)",
    xpub_created: "xpubstore creato",
    wallet_initialized: "walletdb inizializzato",
};

pub const CLI_PT: CliTexts = CliTexts {
    wallet_init_title: "INICIALIZAÇÃO DA CARTEIRA PHANTOM",
    wallet_init_generating: "Uma nova semente BIP39 (24 palavras) está sendo gerada.",
    wallet_init_important: "IMPORTANTE: Escreva as 24 palavras em papel e guarde-as com segurança!",
    wallet_init_write_down: "Sem a semente, a recuperação NÃO é possível.",
    wallet_init_press_enter: "IMPORTANTE: Escreva TODAS as 24 palavras em papel!\nPressione ENTER quando terminar...",
    wallet_init_success: "CARTEIRA CRIADA COM SUCESSO",

    seed_words: "Sua semente de 24 palavras (BIP39 Mnemonic):",

    seed_verify_title: "VERIFICAÇÃO DA SEMENTE",
    seed_verify_hint: "Por segurança: Digite cada palavra quando solicitado.\nA ordem é aleatória - preste atenção ao número!",
    seed_verify_prompt: "Palavra #",
    seed_verify_wrong: "Errado! Correto seria: \"{}\" - por favor corrija em suas notas.",
    seed_verify_correct: "Correto!",
    seed_verify_success: "✓ SEMENTE VERIFICADA COM SUCESSO",

    wallet_restore_title: "RESTAURAÇÃO DA CARTEIRA PHANTOM",
    wallet_restore_enter_seed: "Digite sua semente BIP39 existente (24 palavras).",
    wallet_restore_recognized: "Semente reconhecida ({} palavras). Restaurando carteira...",
    wallet_restore_success: "CARTEIRA RESTAURADA COM SUCESSO",
    wallet_restore_invalid: "Mnemônico inválido",
    wallet_restore_wrong_count: "O mnemônico deve ter 24 palavras, recebido: {}",

    passphrase_enter: "Senha (mín. 8 caracteres, diferencia maiúsculas/minúsculas): ",
    passphrase_policy: "Senha: mín. 8 caracteres, diferencia maiúsculas",

    wallet_name: "Nome da Carteira",
    first_address: "Primeiro Endereço",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "semente salva (criptografada)",
    xpub_created: "xpubstore criado",
    wallet_initialized: "walletdb inicializado",
};

pub const CLI_NL: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM PORTEMONNEE INITIALISATIE",
    wallet_init_generating: "Een nieuwe BIP39 seed (24 woorden) wordt gegenereerd.",
    wallet_init_important: "BELANGRIJK: Schrijf de 24 woorden op papier en bewaar ze veilig!",
    wallet_init_write_down: "Zonder seed is herstel NIET mogelijk.",
    wallet_init_press_enter: "BELANGRIJK: Schrijf ALLE 24 woorden op papier!\nDruk op ENTER als je klaar bent...",
    wallet_init_success: "PORTEMONNEE SUCCESVOL AANGEMAAKT",

    seed_words: "Je 24-woorden seed (BIP39 Mnemonic):",

    seed_verify_title: "SEED VERIFICATIE",
    seed_verify_hint: "Voor veiligheid: Voer elk woord in wanneer gevraagd.\nDe volgorde is willekeurig - let op het nummer!",
    seed_verify_prompt: "Woord #",
    seed_verify_wrong: "Fout! Correct zou zijn: \"{}\" - corrigeer in je notities.",
    seed_verify_correct: "Correct!",
    seed_verify_success: "✓ SEED SUCCESVOL GEVERIFIEERD",

    wallet_restore_title: "PHANTOM PORTEMONNEE HERSTEL",
    wallet_restore_enter_seed: "Voer je bestaande BIP39 seed in (24 woorden).",
    wallet_restore_recognized: "Seed herkend ({} woorden). Portemonnee wordt hersteld...",
    wallet_restore_success: "PORTEMONNEE SUCCESVOL HERSTELD",
    wallet_restore_invalid: "Ongeldige mnemonic",
    wallet_restore_wrong_count: "Mnemonic moet 24 woorden hebben, ontvangen: {}",

    passphrase_enter: "Wachtwoord (min. 8 tekens, hoofdlettergevoelig): ",
    passphrase_policy: "Wachtwoord: min. 8 tekens, hoofdlettergevoelig",

    wallet_name: "Portemonnee Naam",
    first_address: "Eerste Adres",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed opgeslagen (versleuteld)",
    xpub_created: "xpubstore aangemaakt",
    wallet_initialized: "walletdb geïnitialiseerd",
};

pub const CLI_RU: CliTexts = CliTexts {
    wallet_init_title: "ИНИЦИАЛИЗАЦИЯ КОШЕЛЬКА PHANTOM",
    wallet_init_generating: "Генерируется новая BIP39 seed-фраза (24 слова).",
    wallet_init_important: "ВАЖНО: Запишите 24 слова на бумаге и храните их в безопасности!",
    wallet_init_write_down: "Без seed-фразы восстановление НЕВОЗМОЖНО.",
    wallet_init_press_enter: "ВАЖНО: Запишите ВСЕ 24 слова на бумаге!\nНажмите ENTER когда закончите...",
    wallet_init_success: "КОШЕЛЁК УСПЕШНО СОЗДАН",

    seed_words: "Ваша 24-словная seed-фраза (BIP39 Mnemonic):",

    seed_verify_title: "ПРОВЕРКА SEED-ФРАЗЫ",
    seed_verify_hint: "Для безопасности: Введите каждое слово по запросу.\nПорядок случайный - обратите внимание на номер!",
    seed_verify_prompt: "Слово #",
    seed_verify_wrong: "Неверно! Правильно: \"{}\" - исправьте в своих записях.",
    seed_verify_correct: "Правильно!",
    seed_verify_success: "✓ SEED-ФРАЗА УСПЕШНО ПРОВЕРЕНА",

    wallet_restore_title: "ВОССТАНОВЛЕНИЕ КОШЕЛЬКА PHANTOM",
    wallet_restore_enter_seed: "Введите вашу существующую BIP39 seed-фразу (24 слова).",
    wallet_restore_recognized: "Seed-фраза распознана ({} слов). Восстановление кошелька...",
    wallet_restore_success: "КОШЕЛЁК УСПЕШНО ВОССТАНОВЛЕН",
    wallet_restore_invalid: "Недействительный мнемоник",
    wallet_restore_wrong_count: "Мнемоник должен содержать 24 слова, получено: {}",

    passphrase_enter: "Пароль (мин. 8 символов, учитывается регистр): ",
    passphrase_policy: "Пароль: мин. 8 символов, учитывается регистр",

    wallet_name: "Имя Кошелька",
    first_address: "Первый Адрес",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed сохранён (зашифрован)",
    xpub_created: "xpubstore создан",
    wallet_initialized: "walletdb инициализирован",
};

pub const CLI_ZH: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM 钱包初始化",
    wallet_init_generating: "正在生成新的 BIP39 助记词（24个单词）。",
    wallet_init_important: "重要：将24个单词写在纸上并妥善保管！",
    wallet_init_write_down: "没有助记词将无法恢复。",
    wallet_init_press_enter: "重要：将所有24个单词写在纸上！\n完成后按回车键...",
    wallet_init_success: "钱包创建成功",

    seed_words: "您的24个助记词（BIP39 Mnemonic）：",

    seed_verify_title: "助记词验证",
    seed_verify_hint: "为了安全：按提示输入每个单词。\n顺序是随机的 - 注意编号！",
    seed_verify_prompt: "单词 #",
    seed_verify_wrong: "错误！正确的是：\"{}\" - 请在笔记中更正。",
    seed_verify_correct: "正确！",
    seed_verify_success: "✓ 助记词验证成功",

    wallet_restore_title: "PHANTOM 钱包恢复",
    wallet_restore_enter_seed: "输入您现有的 BIP39 助记词（24个单词）。",
    wallet_restore_recognized: "识别到助记词（{} 个单词）。正在恢复钱包...",
    wallet_restore_success: "钱包恢复成功",
    wallet_restore_invalid: "无效的助记词",
    wallet_restore_wrong_count: "助记词必须有24个单词，收到：{}",

    passphrase_enter: "密码（至少8个字符，区分大小写）：",
    passphrase_policy: "密码：至少8个字符，区分大小写",

    wallet_name: "钱包名称",
    first_address: "第一个地址",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "助记词已保存（已加密）",
    xpub_created: "xpubstore 已创建",
    wallet_initialized: "walletdb 已初始化",
};

pub const CLI_JA: CliTexts = CliTexts {
    wallet_init_title: "PHANTOMウォレット初期化",
    wallet_init_generating: "新しいBIP39シード（24単語）を生成中。",
    wallet_init_important: "重要：24単語を紙に書いて安全に保管してください！",
    wallet_init_write_down: "シードなしでは復元できません。",
    wallet_init_press_enter:
        "重要：24単語すべてを紙に書いてください！\n完了したらENTERを押してください...",
    wallet_init_success: "ウォレット作成成功",

    seed_words: "あなたの24単語シード（BIP39 Mnemonic）：",

    seed_verify_title: "シード検証",
    seed_verify_hint:
        "セキュリティのため：各単語を入力してください。\n順番はランダムです - 番号に注意！",
    seed_verify_prompt: "単語 #",
    seed_verify_wrong: "間違い！正解は：\"{}\" - メモを修正してください。",
    seed_verify_correct: "正解！",
    seed_verify_success: "✓ シード検証成功",

    wallet_restore_title: "PHANTOMウォレット復元",
    wallet_restore_enter_seed: "既存のBIP39シード（24単語）を入力してください。",
    wallet_restore_recognized: "シード認識（{}単語）。ウォレットを復元中...",
    wallet_restore_success: "ウォレット復元成功",
    wallet_restore_invalid: "無効なニーモニック",
    wallet_restore_wrong_count: "ニーモニックは24単語必要です。受信：{}",

    passphrase_enter: "パスワード（8文字以上、大文字小文字区別）：",
    passphrase_policy: "パスワード：8文字以上、大文字小文字区別",

    wallet_name: "ウォレット名",
    first_address: "最初のアドレス",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "シード保存済み（暗号化）",
    xpub_created: "xpubstore 作成済み",
    wallet_initialized: "walletdb 初期化済み",
};

pub const CLI_KO: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM 지갑 초기화",
    wallet_init_generating: "새 BIP39 시드(24단어)를 생성 중입니다.",
    wallet_init_important: "중요: 24개의 단어를 종이에 적어 안전하게 보관하세요!",
    wallet_init_write_down: "시드 없이는 복구가 불가능합니다.",
    wallet_init_press_enter:
        "중요: 24개의 단어를 모두 종이에 적으세요!\n완료되면 ENTER를 누르세요...",
    wallet_init_success: "지갑이 성공적으로 생성되었습니다",

    seed_words: "24개의 시드 단어 (BIP39 Mnemonic):",

    seed_verify_title: "시드 검증",
    seed_verify_hint:
        "보안을 위해: 요청 시 각 단어를 입력하세요.\n순서는 무작위입니다 - 번호에 주의하세요!",
    seed_verify_prompt: "단어 #",
    seed_verify_wrong: "틀렸습니다! 정답: \"{}\" - 메모를 수정하세요.",
    seed_verify_correct: "정답!",
    seed_verify_success: "✓ 시드 검증 성공",

    wallet_restore_title: "PHANTOM 지갑 복원",
    wallet_restore_enter_seed: "기존 BIP39 시드(24단어)를 입력하세요.",
    wallet_restore_recognized: "시드 인식됨 ({}단어). 지갑 복원 중...",
    wallet_restore_success: "지갑이 성공적으로 복원되었습니다",
    wallet_restore_invalid: "잘못된 니모닉",
    wallet_restore_wrong_count: "니모닉은 24단어여야 합니다. 받음: {}",

    passphrase_enter: "비밀번호 (최소 8자, 대소문자 구분): ",
    passphrase_policy: "비밀번호: 최소 8자, 대소문자 구분",

    wallet_name: "지갑 이름",
    first_address: "첫 번째 주소",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "시드 저장됨 (암호화)",
    xpub_created: "xpubstore 생성됨",
    wallet_initialized: "walletdb 초기화됨",
};

pub const CLI_TR: CliTexts = CliTexts {
    wallet_init_title: "PHANTOM CÜZDAN BAŞLATMA",
    wallet_init_generating: "Yeni BIP39 seed (24 kelime) oluşturuluyor.",
    wallet_init_important: "ÖNEMLİ: 24 kelimeyi kağıda yazın ve güvenli bir yerde saklayın!",
    wallet_init_write_down: "Seed olmadan kurtarma mümkün DEĞİLDİR.",
    wallet_init_press_enter: "ÖNEMLİ: TÜM 24 kelimeyi kağıda yazın!\nBittiğinde ENTER'a basın...",
    wallet_init_success: "CÜZDAN BAŞARIYLA OLUŞTURULDU",

    seed_words: "24 kelimelik seed'iniz (BIP39 Mnemonic):",

    seed_verify_title: "SEED DOĞRULAMA",
    seed_verify_hint:
        "Güvenlik için: İstendiğinde her kelimeyi girin.\nSıra rastgeledir - numaraya dikkat edin!",
    seed_verify_prompt: "Kelime #",
    seed_verify_wrong: "Yanlış! Doğrusu: \"{}\" - notlarınızda düzeltin.",
    seed_verify_correct: "Doğru!",
    seed_verify_success: "✓ SEED BAŞARIYLA DOĞRULANDI",

    wallet_restore_title: "PHANTOM CÜZDAN GERİ YÜKLEME",
    wallet_restore_enter_seed: "Mevcut BIP39 seed'inizi girin (24 kelime).",
    wallet_restore_recognized: "Seed tanındı ({} kelime). Cüzdan geri yükleniyor...",
    wallet_restore_success: "CÜZDAN BAŞARIYLA GERİ YÜKLENDİ",
    wallet_restore_invalid: "Geçersiz mnemonic",
    wallet_restore_wrong_count: "Mnemonic 24 kelime olmalı, alınan: {}",

    passphrase_enter: "Şifre (min. 8 karakter, büyük/küçük harf duyarlı): ",
    passphrase_policy: "Şifre: min. 8 karakter, büyük/küçük harf duyarlı",

    wallet_name: "Cüzdan Adı",
    first_address: "İlk Adres",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed kaydedildi (şifreli)",
    xpub_created: "xpubstore oluşturuldu",
    wallet_initialized: "walletdb başlatıldı",
};

pub const CLI_AR: CliTexts = CliTexts {
    wallet_init_title: "تهيئة محفظة PHANTOM",
    wallet_init_generating: "يتم إنشاء بذرة BIP39 جديدة (24 كلمة).",
    wallet_init_important: "مهم: اكتب الـ 24 كلمة على ورقة واحفظها بأمان!",
    wallet_init_write_down: "بدون البذرة، الاسترداد غير ممكن.",
    wallet_init_press_enter: "مهم: اكتب جميع الـ 24 كلمة على ورقة!\nاضغط ENTER عند الانتهاء...",
    wallet_init_success: "تم إنشاء المحفظة بنجاح",

    seed_words: "بذرتك المكونة من 24 كلمة (BIP39 Mnemonic):",

    seed_verify_title: "التحقق من البذرة",
    seed_verify_hint: "للأمان: أدخل كل كلمة عند الطلب.\nالترتيب عشوائي - انتبه للرقم!",
    seed_verify_prompt: "كلمة #",
    seed_verify_wrong: "خطأ! الصحيح: \"{}\" - صحح في ملاحظاتك.",
    seed_verify_correct: "صحيح!",
    seed_verify_success: "✓ تم التحقق من البذرة بنجاح",

    wallet_restore_title: "استعادة محفظة PHANTOM",
    wallet_restore_enter_seed: "أدخل بذرة BIP39 الموجودة (24 كلمة).",
    wallet_restore_recognized: "تم التعرف على البذرة ({} كلمة). جاري استعادة المحفظة...",
    wallet_restore_success: "تم استعادة المحفظة بنجاح",
    wallet_restore_invalid: "مفتاح تذكيري غير صالح",
    wallet_restore_wrong_count: "يجب أن يحتوي المفتاح التذكيري على 24 كلمة، تم استلام: {}",

    passphrase_enter: "كلمة المرور (8 أحرف على الأقل): ",
    passphrase_policy: "كلمة المرور: 8 أحرف على الأقل",

    wallet_name: "اسم المحفظة",
    first_address: "العنوان الأول",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "تم حفظ البذرة (مشفرة)",
    xpub_created: "تم إنشاء xpubstore",
    wallet_initialized: "تم تهيئة walletdb",
};

pub const CLI_PL: CliTexts = CliTexts {
    wallet_init_title: "INICJALIZACJA PORTFELA PHANTOM",
    wallet_init_generating: "Generowanie nowego seeda BIP39 (24 słowa).",
    wallet_init_important: "WAŻNE: Zapisz 24 słowa na papierze i przechowuj je bezpiecznie!",
    wallet_init_write_down: "Bez seeda odzyskanie NIE jest możliwe.",
    wallet_init_press_enter: "WAŻNE: Zapisz WSZYSTKIE 24 słowa na papierze!\nNaciśnij ENTER gdy skończysz...",
    wallet_init_success: "PORTFEL UTWORZONY POMYŚLNIE",

    seed_words: "Twój 24-słowny seed (BIP39 Mnemonic):",

    seed_verify_title: "WERYFIKACJA SEEDA",
    seed_verify_hint: "Dla bezpieczeństwa: Wprowadź każde słowo gdy zostaniesz poproszony.\nKolejność jest losowa - zwróć uwagę na numer!",
    seed_verify_prompt: "Słowo #",
    seed_verify_wrong: "Źle! Poprawne: \"{}\" - popraw w swoich notatkach.",
    seed_verify_correct: "Poprawnie!",
    seed_verify_success: "✓ SEED ZWERYFIKOWANY POMYŚLNIE",

    wallet_restore_title: "PRZYWRACANIE PORTFELA PHANTOM",
    wallet_restore_enter_seed: "Wprowadź istniejący seed BIP39 (24 słowa).",
    wallet_restore_recognized: "Seed rozpoznany ({} słów). Przywracanie portfela...",
    wallet_restore_success: "PORTFEL PRZYWRÓCONY POMYŚLNIE",
    wallet_restore_invalid: "Nieprawidłowy mnemonik",
    wallet_restore_wrong_count: "Mnemonik musi mieć 24 słowa, otrzymano: {}",

    passphrase_enter: "Hasło (min. 8 znaków, wielkość liter ma znaczenie): ",
    passphrase_policy: "Hasło: min. 8 znaków, wielkość liter ma znaczenie",

    wallet_name: "Nazwa Portfela",
    first_address: "Pierwszy Adres",
    wallet_db: "WalletDb",
    xpub_store: "XpubStore",
    seed_store: "SeedStore",
    seed_saved: "seed zapisany (zaszyfrowany)",
    xpub_created: "xpubstore utworzony",
    wallet_initialized: "walletdb zainicjalizowany",
};

pub fn cli_texts(lang: Lang) -> &'static CliTexts {
    match lang {
        Lang::En => &CLI_EN,
        Lang::De => &CLI_DE,
        Lang::Es => &CLI_ES,
        Lang::Fr => &CLI_FR,
        Lang::It => &CLI_IT,
        Lang::Pt => &CLI_PT,
        Lang::Nl => &CLI_NL,
        Lang::Ru => &CLI_RU,
        Lang::Zh => &CLI_ZH,
        Lang::Ja => &CLI_JA,
        Lang::Ko => &CLI_KO,
        Lang::Tr => &CLI_TR,
        Lang::Ar => &CLI_AR,
        Lang::Pl => &CLI_PL,
    }
}
