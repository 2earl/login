import type { Catalog } from '../i18n';

/**
 * Turkish (DESIGN §4.31). Keys are the English sentences exactly as the pages and emails write
 * them; see src/i18n.ts for markers (<0>…</0>, <0/>) and placeholders ({0}).
 *
 * Words: account → hesap, sign in → giriş yap, sign-in method → giriş yöntemi, passkey → geçiş
 * anahtarı, second factor → ikinci doğrulama adımı, authenticator app → doğrulama uygulaması,
 * recovery code → kurtarma kodu, organization → kurum, owner → sahip, admin → yönetici,
 * auditor → denetçi, member → üye, app → uygulama, connected app → bağlı uygulama,
 * single sign-on → çoklu oturum açma (SSO), directory sync → dizin eşitlemesi, managed → yönetilen.
 */
export const tr: Catalog = {
  months: [
    'Ocak',
    'Şubat',
    'Mart',
    'Nisan',
    'Mayıs',
    'Haziran',
    'Temmuz',
    'Ağustos',
    'Eylül',
    'Ekim',
    'Kasım',
    'Aralık',
  ],
  monthsShort: ['Oca', 'Şub', 'Mar', 'Nis', 'May', 'Haz', 'Tem', 'Ağu', 'Eyl', 'Eki', 'Kas', 'Ara'],
  messages: {
    '1 organization. Open one to see its members and setup. Suspending one freezes it: members can only leave, and 2earl services stop seeing it.':
      '1 kurum. Üyelerini ve kurulumunu görmek için açın. Askıya almak kurumu dondurur: üyeler yalnızca ayrılabilir ve 2earl hizmetleri onu artık görmez.',
    '1 to 100 (default 100)': '1 ile 100 arası (varsayılan 100)',
    '2earl MCP gateway ({0})': '2earl MCP ağ geçidi ({0})',
    '2earl invited you to set up your organization on 2earl. You’ll be its owner: you add the people who run it with you (admins) and everyone else, and connect your company’s sign-in and directory when you’re ready.':
      '2earl sizi 2earl’de kurumunuzu kurmaya davet etti. Kurumun sahibi siz olacaksınız: onu sizinle birlikte yönetecek kişileri (yöneticiler) ve diğer herkesi siz eklersiniz; hazır olduğunuzda şirketinizin giriş hizmetini ve dizinini bağlarsınız.',
    '2earl invited you to set up “{0}” on 2earl. You’ll be its owner: you add the people who run it with you (admins) and everyone else, and connect your company’s sign-in and directory when you’re ready.':
      '2earl sizi 2earl’de “{0}” kurumunu kurmaya davet etti. Kurumun sahibi siz olacaksınız: onu sizinle birlikte yönetecek kişileri (yöneticiler) ve diğer herkesi siz eklersiniz; hazır olduğunuzda şirketinizin giriş hizmetini ve dizinini bağlarsınız.',
    '2earl invited you. The invitation works until {0}.':
      '2earl sizi davet etti. Davet {0} tarihine kadar geçerli.',
    '2earl invited {0} to set up an organization. You’ll be its owner: you add the admins who help you run it, and everyone else, and connect your company’s sign-in and directory when you’re ready.':
      '2earl, {0} adresini bir kurum kurmaya davet etti. Kurumun sahibi siz olacaksınız: onu yönetmenize yardım edecek yöneticileri ve diğer herkesi siz eklersiniz; hazır olduğunuzda şirketinizin giriş hizmetini ve dizinini bağlarsınız.',
    '2earl invites the person who will run an organization. They get an email, sign in with that address and name the organization; they then add the admins and members.':
      '2earl, bir kurumu yönetecek kişiyi davet eder. O kişi bir e-posta alır, o adresle giriş yapar ve kuruma bir ad verir; ardından yöneticileri ve üyeleri ekler.',
    '2earl requires a second factor, so your only one can’t be removed. Add another first.':
      '2earl ikinci bir doğrulama adımı gerektirir, bu yüzden tek adımınız kaldırılamaz. Önce bir tane daha ekleyin.',
    '2earl requires a second factor. Add another one before removing this one.':
      '2earl ikinci bir doğrulama adımı gerektirir. Bunu kaldırmadan önce bir tane daha ekleyin.',
    '2earl requires a second factor. Add one to continue to your account.':
      '2earl ikinci bir doğrulama adımı gerektirir. Hesabınıza devam etmek için bir tane ekleyin.',
    '2earl support signed your account out on every device, usually because you asked for help with a lost or shared device. Connected apps lost access too.':
      '2earl destek ekibi, genellikle kaybolan veya paylaşılan bir cihaz için yardım istediğiniz için, hesabınızın tüm cihazlardaki oturumlarını kapattı. Bağlı uygulamaların erişimi de sona erdi.',
    '2earl support signed your account out on every device.':
      '2earl destek ekibi hesabınızın tüm cihazlardaki oturumlarını kapattı.',
    '2earl took new SAML signing certificates from your identity provider’s metadata URL in “{0}”.':
      '2earl, “{0}” kurumunda kimlik sağlayıcınızın meta veri adresinden yeni SAML imzalama sertifikaları aldı.',
    '2earl took new SAML signing certificates from your identity provider’s metadata URL.':
      '2earl, kimlik sağlayıcınızın meta veri adresinden yeni SAML imzalama sertifikaları aldı.',
    '7 days (2earl’s default)': '7 gün (2earl varsayılanı)',
    '<0/> from the previous page: events after it': 'Önceki sayfadaki <0/>: ondan sonraki olaylar',
    '<0/>, <1/> or <2/>': '<0/>, <1/> veya <2/>',
    '<0>Access:</0> a <1>read</1> key reads; a <2>read and write</2> key also changes members.':
      '<0>Erişim:</0> <1>okuma</1> anahtarı yalnızca okur; <2>okuma ve yazma</2> anahtarı üyeleri de değiştirir.',
    '<0>Admins</0> run 2earl: users, sign-up, organizations and their invitations, apps. They can’t give or take staff roles or act on other staff. <1>Support</1> helps people and organizations: sees users, organizations and the security log, signs a person out everywhere, sends a waiting organization invitation again. Only you, the owner, change who is staff. Staff need a second factor.':
      '<0>Yöneticiler</0> 2earl’ü yürütür: kullanıcılar, kayıt, kurumlar ve davetleri, uygulamalar. Ekip rolleri veremez, geri alamaz ve diğer ekip üyeleri üzerinde işlem yapamazlar. <1>Destek</1> kişilere ve kurumlara yardım eder: kullanıcıları, kurumları ve güvenlik kaydını görür, birinin tüm oturumlarını kapatır, bekleyen bir kurum davetini yeniden gönderir. Ekipte kimin olacağını yalnızca siz, sahip olarak değiştirirsiniz. Ekip üyelerinin ikinci bir doğrulama adımı olmalıdır.',
    '<0>By invitation.</0> New accounts need an invitation below. Accounts that already exist keep working.':
      '<0>Davetle.</0> Yeni hesaplar için aşağıdan bir davet gerekir. Mevcut hesaplar çalışmaya devam eder.',
    '<0>Changes are pushed</0> by the audit stream (Activity → Stream), not by polling.':
      '<0>Değişiklikler</0> sorgulamayla değil, denetim akışıyla (Etkinlik → Akış) gönderilir.',
    '<0>Copy the secret now.</0> It isn’t stored and won’t be shown again.':
      '<0>Sırrı şimdi kopyalayın.</0> Saklanmaz ve bir daha gösterilmez.',
    '<0>Filters:</0> <1/>, <2/> (users); <3/>, <4/> (groups). <5/> on groups.':
      '<0>Filtreler:</0> <1/>, <2/> (kullanıcılar); <3/>, <4/> (gruplar). Gruplarda <5/>.',
    '<0>Format:</0> JSON. Lists are <1/>. Errors are <2/> with a 4xx status.':
      '<0>Biçim:</0> JSON. Listeler <1/> biçimindedir. Hatalar 4xx durum koduyla <2/> biçimindedir.',
    '<0>Limits:</0> up to 5 keys per organization; requests are rate-limited per network address (<1/>).':
      '<0>Sınırlar:</0> kurum başına en fazla 5 anahtar; istekler ağ adresi başına sınırlanır (<1/>).',
    '<0>Not supported:</0> bulk, sorting, ETags, soft delete.':
      '<0>Desteklenmez:</0> toplu işlemler, sıralama, ETag’ler, geçici silme.',
    '<0>Owners:</0> the API never acts on them. Change owners in 2earl.':
      '<0>Sahipler:</0> API onlar üzerinde asla işlem yapmaz. Sahipleri 2earl’de değiştirin.',
    '<0>Resources:</0> <1/> and <2/>: create, read, list, replace, patch, delete. <3/> takes the shapes Entra ID and Okta send, operation names in any case.':
      '<0>Kaynaklar:</0> <1/> ve <2/>: oluşturma, okuma, listeleme, değiştirme, yamalama, silme. <3/>, Entra ID ve Okta’nın gönderdiği biçimleri ve her büyüklükte işlem adlarını kabul eder.',
    '<0>Your new key.</0> Copy it now: it isn’t shown again.':
      '<0>Yeni anahtarınız.</0> Şimdi kopyalayın: bir daha gösterilmez.',
    '<0>Your new token.</0> Copy it into your directory now: it isn’t shown again.':
      '<0>Yeni token’ınız.</0> Şimdi dizininize kopyalayın: bir daha gösterilmez.',
    '<0>Your signing secret.</0> Put it in your receiving endpoint now: it isn’t shown again.':
      '<0>İmzalama sırrınız.</0> Şimdi alıcı uç noktanıza ekleyin: bir daha gösterilmez.',
    'A 2earl account': 'Bir 2earl hesabı',
    'A Google account can sign in to one 2earl account only. Nothing was changed':
      'Bir Google hesabı yalnızca bir 2earl hesabına giriş yapabilir. Hiçbir şey değiştirilmedi',
    'A Google account can sign in to one 2earl account only. Nothing was changed.':
      'Bir Google hesabı yalnızca bir 2earl hesabına giriş yapabilir. Hiçbir şey değiştirilmedi.',
    'A code by email': 'E-postayla kod',
    "A managed account can't sign in; sessions and app access end. <0/> otherwise":
      'Yönetilen hesap giriş yapamaz; oturumlar ve uygulama erişimi sona erer. Aksi halde <0/>',
    'A passkey': 'Geçiş anahtarı',
    'A passkey now protects your 2earl account.':
      '2earl hesabınızı artık bir geçiş anahtarı koruyor.',
    'A passkey now protects your account.': 'Hesabınızı artık bir geçiş anahtarı koruyor.',
    'A second factor was added': 'İkinci bir doğrulama adımı eklendi',
    'A second factor was added to your 2earl account':
      '2earl hesabınıza ikinci bir doğrulama adımı eklendi',
    'A second factor was removed': 'Bir doğrulama adımı kaldırıldı',
    'A second factor was removed from your 2earl account':
      '2earl hesabınızdan bir doğrulama adımı kaldırıldı',
    'A security setting changed': 'Bir güvenlik ayarı değişti',
    'A sign-in method was added': 'Bir giriş yöntemi eklendi',
    'A sign-in method was added to your 2earl account':
      '2earl hesabınıza bir giriş yöntemi eklendi',
    'A sign-in method was removed': 'Bir giriş yöntemi kaldırıldı',
    'A sign-in method was removed from your 2earl account':
      '2earl hesabınızdan bir giriş yöntemi kaldırıldı',
    'API keys': 'API anahtarları',
    'API reference': 'API başvurusu',
    Access: 'Erişim',
    'Access for your connected app': 'Bağlı uygulamanızın erişimi',
    'Access will be sent to an app on your own computer. Continue only if you just started signing in from that app':
      'Erişim kendi bilgisayarınızdaki bir uygulamaya gönderilecek. Yalnızca o uygulamadan girişi az önce başlattıysanız devam edin',
    'Access will be sent to an app on your own computer. Continue only if you just started signing in from that app.':
      'Erişim kendi bilgisayarınızdaki bir uygulamaya gönderilecek. Yalnızca o uygulamadan girişi az önce başlattıysanız devam edin.',
    Account: 'Hesap',
    'Account became managed': 'Hesap yönetilen oldu',
    'Account created': 'Hesap oluşturuldu',
    'Account deactivated. It can’t sign in, and its apps lost access':
      'Hesap devre dışı bırakıldı. Giriş yapamaz ve uygulamaları erişimini kaybetti',
    'Account deactivated. It can’t sign in, and its apps lost access.':
      'Hesap devre dışı bırakıldı. Giriş yapamaz ve uygulamaları erişimini kaybetti.',
    'Account deleted': 'Hesap silindi',
    'Account deleted, in every 2earl service': 'Hesap her 2earl hizmetinde silindi',
    'Account deleted, in every 2earl service.': 'Hesap her 2earl hizmetinde silindi.',
    'Account deleted.': 'Hesap silindi.',
    'Account deletion started': 'Hesap silme başladı',
    'Account deletion stopped': 'Hesap silme durdu',
    'Account kept personal': 'Hesap kişisel tutuldu',
    'Account reactivated. It can sign in again':
      'Hesap yeniden etkinleştirildi. Yeniden giriş yapabilir',
    'Account reactivated. It can sign in again.':
      'Hesap yeniden etkinleştirildi. Yeniden giriş yapabilir.',
    'Account: 2earl. Type: time-based. Six digits, every 30 seconds.':
      'Hesap: 2earl. Tür: zamana dayalı. Her 30 saniyede bir altı haneli kod.',
    Accounts: 'Hesaplar',
    'Accounts at the domain are managed now. People who already had one choose at their next sign-in':
      'Alan adındaki hesaplar artık yönetiliyor. Zaten hesabı olanlar bir sonraki girişlerinde seçim yapar',
    'Accounts at the domain are managed now. People who already had one choose at their next sign-in.':
      'Alan adındaki hesaplar artık yönetiliyor. Zaten hesabı olanlar bir sonraki girişlerinde seçim yapar.',
    'Accounts at the domain become your organization’s to deactivate and delete.':
      'Alan adındaki hesapları kurumunuz devre dışı bırakabilir ve silebilir.',
    'Accounts at {0} sign in through their organization’s single sign-on.':
      '{0} adresindeki hesaplar kurumlarının çoklu oturum açma hizmetiyle giriş yapar.',
    'Accounts managed': 'Hesaplar yönetiliyor',
    'Active now': 'Şu an etkin',
    'Active {0} day ago': '{0} gün önce etkin',
    'Active {0} days ago': '{0} gün önce etkin',
    'Active {0} hour ago': '{0} saat önce etkin',
    'Active {0} hours ago': '{0} saat önce etkin',
    'Active {0} minutes ago': '{0} dakika önce etkin',
    Activity: 'Etkinlik',
    'Add Google': 'Google ekle',
    'Add a passkey': 'Geçiş anahtarı ekle',
    'Add a passkey or an authenticator app as a second factor. Then nobody can use your account with your email alone.':
      'İkinci doğrulama adımı olarak bir geçiş anahtarı veya doğrulama uygulaması ekleyin. Böylece kimse hesabınızı yalnızca e-postanızla kullanamaz.',
    'Add a second factor': 'İkinci doğrulama adımı ekle',
    'Add a second factor to your own account first. Owners can still sign in without single sign-on, so their accounts need one.':
      'Önce kendi hesabınıza ikinci bir doğrulama adımı ekleyin. Sahipler çoklu oturum açma olmadan da giriş yapabildiği için hesaplarının buna ihtiyacı var.',
    'Add an email address': 'E-posta adresi ekle',
    'Add another way to sign in first, then remove the address.':
      'Önce başka bir giriş yolu ekleyin, sonra adresi kaldırın.',
    'Add domain': 'Alan adı ekle',
    'Add this TXT record to the domain’s DNS, then check:':
      'Bu TXT kaydını alan adının DNS’ine ekleyin, ardından denetleyin:',
    'Add this address': 'Bu adresi ekle',
    'Add this address in the same browser': 'Bu adresi aynı tarayıcıda ekleyin',
    'Add to staff': 'Ekibe ekle',
    'Added a second factor': 'İkinci doğrulama adımı ekledi',
    'Added a way to sign in': 'Bir giriş yolu ekledi',
    'Added {0}': '{0} tarihinde eklendi',
    'Adding a passkey needs JavaScript.': 'Geçiş anahtarı eklemek için JavaScript gerekir.',
    'Adding or removing a factor asks for your second factor again if you last used it more than 5 minutes ago.':
      'Bir doğrulama adımı eklemek veya kaldırmak, ikinci adımınızı en son 5 dakikadan önce kullandıysanız onu yeniden ister.',
    Admin: 'Yönetici',
    'Admin actions': 'Yönetici işlemleri',
    'Admin needs a second factor': 'Yönetim için ikinci bir doğrulama adımı gerekir',
    'Admins can invite people, remove members and admins, and change their roles. Everyone here sees each member’s name and email address.':
      'Yöneticiler kişileri davet edebilir, üyeleri ve yöneticileri çıkarabilir ve rollerini değiştirebilir. Buradaki herkes her üyenin adını ve e-posta adresini görür.',
    'After signing in with Google, you confirm it’s you with something only you have. Someone who gets into your Google account still can’t get into 2earl.':
      'Google ile giriş yaptıktan sonra, yalnızca sizde olan bir şeyle kimliğinizi doğrularsınız. Google hesabınıza giren biri yine de 2earl’e giremez.',
    'All events': 'Tüm olaylar',
    Allow: 'İzin ver',
    'Allow <0>{0}</0> to use your 2earl account?': '<0>{0}</0> 2earl hesabınızı kullanabilsin mi?',
    'Allow another app': 'Başka bir uygulamaya izin ver',
    'Allow at least one way to sign in, or turn on single sign-on first.':
      'En az bir giriş yoluna izin verin ya da önce çoklu oturum açmayı açın.',
    'Allow {0}?': '{0} için izin verilsin mi?',
    Allowed: 'İzin verildi',
    'Allowed an app': 'Bir uygulamaya izin verdi',
    'Allowed networks': 'İzin verilen ağlar',
    'Allowed on {0}': '{0} tarihinde izin verildi',
    'Allowed {0}': '{0} uygulamasına izin verdi',
    'An account can be in 50 organizations. Leave one, then open the invitation again':
      'Bir hesap 50 kurumda olabilir. Birinden ayrılın, ardından daveti yeniden açın',
    'An account can be in 50 organizations. Leave one, then open the invitation again.':
      'Bir hesap 50 kurumda olabilir. Birinden ayrılın, ardından daveti yeniden açın.',
    'An account that signs in with Google uses this address. Continue with Google, then add email sign-in on your account page if you like.':
      'Bu adresi Google ile giriş yapan bir hesap kullanıyor. Google ile devam edin; isterseniz ardından hesap sayfanızda e-postayla girişi ekleyin.',
    'An account that signs in with an email code uses this address. Sign in with email, then add Google on your account page, so both work.':
      'Bu adresi e-posta koduyla giriş yapan bir hesap kullanıyor. E-postayla giriş yapın, ardından ikisi de çalışsın diye hesap sayfanızda Google’ı ekleyin.',
    'An address can sign in to one 2earl account only. Nothing was changed.':
      'Bir adres yalnızca bir 2earl hesabına giriş yapabilir. Hiçbir şey değiştirilmedi.',
    'An app can now act for you': 'Bir uygulama artık sizin adınıza işlem yapabilir',
    'An authenticator app no longer protects your 2earl account.':
      '2earl hesabınızı artık bir doğrulama uygulaması korumuyor.',
    'An authenticator app no longer protects your account.':
      'Hesabınızı artık bir doğrulama uygulaması korumuyor.',
    'An authenticator app now protects your 2earl account.':
      '2earl hesabınızı artık bir doğrulama uygulaması koruyor.',
    'An authenticator app now protects your account.':
      'Hesabınızı artık bir doğrulama uygulaması koruyor.',
    'An invitation names a Google account’s address, or an address that signs in with email codes. At the first Google sign-in it is pinned to that Google account. Withdrawing one doesn’t sign anyone out; suspend the user for that.':
      'Bir davet, bir Google hesabının adresini ya da e-posta koduyla giriş yapan bir adresi belirtir. İlk Google girişinde o Google hesabına sabitlenir. Daveti geri almak kimsenin oturumunu kapatmaz; bunun için kullanıcıyı askıya alın.',
    'An organization can allow up to 200 apps': 'Bir kurum en fazla 200 uygulamaya izin verebilir',
    'An organization can allow up to 200 apps.':
      'Bir kurum en fazla 200 uygulamaya izin verebilir.',
    'An organization can have up to 10 domains': 'Bir kurumun en fazla 10 alan adı olabilir',
    'An organization can have up to 10 domains.': 'Bir kurumun en fazla 10 alan adı olabilir.',
    'An organization can have up to 5 keys. Revoke one first':
      'Bir kurumun en fazla 5 anahtarı olabilir. Önce birini iptal edin',
    'An organization can have up to 5 keys. Revoke one first.':
      'Bir kurumun en fazla 5 anahtarı olabilir. Önce birini iptal edin.',
    'An owner of the organization?': 'Kurumun sahiplerinden biri misiniz?',
    'Another organization already manages your account, so this address can only be removed from it':
      'Hesabınızı zaten başka bir kurum yönettiği için bu adres yalnızca hesaptan kaldırılabilir',
    'Another organization already manages your account, so this address can only be removed from it.':
      'Hesabınızı zaten başka bir kurum yönettiği için bu adres yalnızca hesaptan kaldırılabilir.',
    'Another organization has already verified this domain.':
      'Bu alan adını başka bir kurum zaten doğruladı.',
    App: 'Uygulama',
    'App access': 'Uygulama erişimi',
    'App access refused': 'Uygulama erişimi reddedildi',
    'App allowed': 'Uygulamaya izin verildi',
    'App allowed (remembered)': 'Uygulamaya izin verildi (hatırlanan)',
    'App can now act for you': 'Uygulama artık sizin adınıza işlem yapabilir',
    'App deleted and its access revoked': 'Uygulama silindi ve erişimi iptal edildi',
    'App deleted and its access revoked.': 'Uygulama silindi ve erişimi iptal edildi.',
    'App disconnected': 'Uygulama bağlantısı kesildi',
    'App marked as verified': 'Uygulama doğrulanmış olarak işaretlendi',
    'App marked as verified.': 'Uygulama doğrulanmış olarak işaretlendi.',
    'App marked verified': 'Uygulama doğrulanmış olarak işaretlendi',
    'App name': 'Uygulama adı',
    'App refused by the user': 'Uygulama kullanıcı tarafından reddedildi',
    'App registered': 'Uygulama kaydedildi',
    'App registered. Its client ID is {0}.': 'Uygulama kaydedildi. İstemci kimliği {0}.',
    'App removed': 'Uygulama kaldırıldı',
    'App removed. Its access ends within 15 minutes':
      'Uygulama kaldırıldı. Erişimi 15 dakika içinde sona erer',
    'App removed. Its access ends within 15 minutes.':
      'Uygulama kaldırıldı. Erişimi 15 dakika içinde sona erer.',
    'App unmarked': 'Uygulama işareti kaldırıldı',
    'Approval pages work once, for ten minutes, in the browser that opened them. Return to the app and connect again.':
      'Onay sayfaları, onları açan tarayıcıda bir kez ve on dakika boyunca çalışır. Uygulamaya dönün ve yeniden bağlanın.',
    'Approval stopped': 'Onay durduruldu',
    Apps: 'Uygulamalar',
    'Apps you allowed to act for you. Disconnecting one ends its access within about a minute.':
      'Sizin adınıza işlem yapmasına izin verdiğiniz uygulamalar. Birinin bağlantısını kesmek erişimini yaklaşık bir dakika içinde sona erdirir.',
    'Apps you used before need to be connected again.':
      'Daha önce kullandığınız uygulamaların yeniden bağlanması gerekir.',
    'At a domain the organization manages, provisioning creates the 2earl account; <0/> deactivates it; <1/> deactivates it at once and deletes it 30 days later unless it is reactivated first. Groups can be marked admins or auditors on <2>Domains &amp; SSO</2>: their members get that role.':
      'Kurumun yönettiği bir alan adında hesap açma işlemi 2earl hesabını oluşturur; <0/> hesabı devre dışı bırakır; <1/> hesabı hemen devre dışı bırakır ve daha önce yeniden etkinleştirilmezse 30 gün sonra siler. Gruplar <2>Alan adları ve SSO</2> sayfasında yönetici veya denetçi olarak işaretlenebilir: üyeleri o rolü alır.',
    'At a glance': 'Özet',
    Auditor: 'Denetçi',
    'Auditor (read-only)': 'Denetçi (salt okunur)',
    'Auditors see the members and the activity, and can download it, but can’t change anything. Everyone here sees each member’s name and email address.':
      'Denetçiler üyeleri ve etkinliği görür ve indirebilir, ama hiçbir şeyi değiştiremez. Buradaki herkes her üyenin adını ve e-posta adresini görür.',
    Authentication: 'Kimlik doğrulama',
    'Authentication:': 'Kimlik doğrulama:',
    'Authenticator app': 'Doğrulama uygulaması',
    'Available once you manage the accounts at a domain (step 2 above).':
      'Bir alan adındaki hesapları yönetmeye başladığınızda kullanılabilir (yukarıdaki 2. adım).',
    'Available once you manage the accounts at a domain (step 2 above). This is what you’ll set:':
      'Bir alan adındaki hesapları yönetmeye başladığınızda kullanılabilir (yukarıdaki 2. adım). Ayarlayacaklarınız:',
    'Back to sign-in': 'Girişe dön',
    'Back to your account': 'Hesabınıza dönün',
    'Back to your organizations': 'Kurumlarınıza dönün',
    'Backup server': 'Yedek sunucu',
    'Base URL': 'Temel URL',
    'Base URL:': 'Temel URL:',
    'Bearer token (below)': 'Bearer token (aşağıda)',
    'Became owner (previous owner deleted)': 'Sahip oldu (önceki sahip silindi)',
    Body: 'Gövde',
    By: 'Yapan',
    'By continuing, you agree to the <0>Terms of service</0> and acknowledge the <1>Privacy policy</1>.':
      'Devam ederek <0>Kullanım koşullarını</0> kabul etmiş ve <1>Gizlilik politikasını</1> okumuş olursunuz.',
    Cancel: 'İptal',
    'Can’t scan it? Enter the key instead': 'Tarayamıyor musunuz? Bunun yerine anahtarı girin',
    Change: 'Değiştir',
    'Change name': 'Adı değiştir',
    'Changes the role. <0/> when the directory decides it (a group marked admin or auditor)':
      'Rolü değiştirir. Rolü dizin belirliyorsa (yönetici veya denetçi olarak işaretlenmiş bir grup) <0/>',
    'Check DNS': 'DNS’i denetle',
    'Check and save': 'Denetle ve kaydet',
    'Check the link, or go to your account.': 'Bağlantıyı denetleyin ya da hesabınıza gidin.',
    'Check your email': 'E-postanızı kontrol edin',
    'Check your spam folder, and that the address is right. Codes can take a minute.':
      'İstenmeyen e-posta klasörünüze ve adresin doğru olduğuna bakın. Kodların gelmesi bir dakika sürebilir.',
    'Checks tokens for': 'Şunlar için token denetler',
    'Choose a resource.': 'Bir kaynak seçin.',
    'Choose a session length from the list.': 'Listeden bir oturum süresi seçin.',
    'Choose admin or support': 'Yönetici ya da destek seçin',
    'Choose admin or support.': 'Yönetici ya da destek seçin.',
    'Choose now': 'Şimdi seçin',
    'Choose whether it manages your account, the next time you sign in.':
      'Hesabınızı onun yönetip yönetmeyeceğini bir sonraki girişinizde seçin.',
    'Choose which apps the accounts you manage may connect, owners’ too. Apps that aren’t allowed lose access within 15 minutes.':
      'Yönettiğiniz hesapların (sahiplerinkiler dahil) hangi uygulamaları bağlayabileceğini seçin. İzin verilmeyen uygulamalar 15 dakika içinde erişimini kaybeder.',
    'Chrome on Android': 'Android üzerinde Chrome',
    'Chrome on ChromeOS': 'ChromeOS üzerinde Chrome',
    'Chrome on Linux': 'Linux üzerinde Chrome',
    'Chrome on Windows': 'Windows üzerinde Chrome',
    'Chrome on iPad': 'iPad üzerinde Chrome',
    'Chrome on iPhone': 'iPhone üzerinde Chrome',
    'Chrome on macOS': 'macOS üzerinde Chrome',
    'Client ID': 'İstemci kimliği',
    'Client ID (the app’s metadata URL, or a registered client ID)':
      'İstemci kimliği (uygulamanın meta veri adresi ya da kayıtlı bir istemci kimliği)',
    'Client ID <0/>': 'İstemci kimliği <0/>',
    'Client authentication': 'İstemci kimlik doğrulaması',
    'Client secret': 'İstemci sırrı',
    'Client secret (basic)': 'İstemci sırrı (basic)',
    'Client secret expires (optional)': 'İstemci sırrının bitiş tarihi (isteğe bağlı)',
    'Close sign-up (invitation only)': 'Kaydı kapat (yalnızca davetle)',
    Code: 'Kod',
    'Code from the app': 'Uygulamadaki kod',
    'Code from your authenticator app': 'Doğrulama uygulamanızdaki kod',
    'Codes work once, for 10 minutes, in the browser that asked for them, and stop after 5 wrong tries. Ask for a new one.':
      'Kodlar, onları isteyen tarayıcıda bir kez ve 10 dakika boyunca çalışır; 5 yanlış denemeden sonra geçersiz olur. Yeni bir kod isteyin.',
    'Confirm deleting your account': 'Hesabınızı silmeyi onaylayın',
    'Confirm deletion': 'Silmeyi onaylayın',
    'Confirm deletion in the same browser': 'Silmeyi aynı tarayıcıda onaylayın',
    'Confirm it’s you': 'Kimliğinizi doğrulayın',
    'Confirm it’s you again, then add the passkey':
      'Kimliğinizi yeniden doğrulayın, ardından geçiş anahtarını ekleyin',
    'Confirm it’s you again, then add the passkey.':
      'Kimliğinizi yeniden doğrulayın, ardından geçiş anahtarını ekleyin.',
    'Confirm with Google': 'Google ile doğrulayın',
    'Confirm with an email code': 'E-posta koduyla doğrulayın',
    'Confirm your address': 'Adresinizi doğrulayın',
    'Confirm your email address': 'E-posta adresinizi doğrulayın',
    'Connect single sign-on': 'Çoklu oturum açmayı bağla',
    'Connect your directory': 'Dizininizi bağlayın',
    'Connected apps': 'Bağlı uygulamalar',
    'Connected apps: none right now': 'Bağlı uygulamalar: şu an yok',
    'Connection stopped': 'Bağlantı durduruldu',
    Consent: 'Onay',
    Continue: 'Devam et',
    'Continue in this browser.': 'Bu tarayıcıda devam edin.',
    'Continue to 2earl': '2earl’e devam et',
    'Continue with Google': 'Google ile devam et',
    'Continue with email': 'E-postayla devam et',
    'Continue with single sign-on': 'Çoklu oturum açmayla devam et',
    'Couldn’t read the provider’s configuration at {0}, or it names another issuer. Check the issuer URL.':
      'Sağlayıcının {0} adresindeki yapılandırması okunamadı ya da başka bir yayıncıyı belirtiyor. Yayıncı (issuer) URL’sini denetleyin.',
    'Counted from sign-in. Sessions end after 12 hours unused in any case.':
      'Girişten itibaren sayılır. Oturumlar her durumda 12 saat kullanılmayınca sona erer.',
    'Create a new client secret at your identity provider and save it, with its expiry date, on Domains & SSO before the old one stops working.':
      'Eskisi çalışmayı bırakmadan önce kimlik sağlayıcınızda yeni bir istemci sırrı oluşturun ve bitiş tarihiyle birlikte Alan adları ve SSO sayfasına kaydedin.',
    'Create a token': 'Token oluştur',
    'Create an organization': 'Kurum oluştur',
    'Create credentials': 'Kimlik bilgileri oluştur',
    'Create key': 'Anahtar oluştur',
    'Create new codes': 'Yeni kodlar oluştur',
    'Create one': 'Bir tane oluşturun',
    'Create one yourself': 'Kendiniz oluşturun',
    'Create organization': 'Kurumu oluştur',
    'Create the stream': 'Akışı oluştur',
    'Create, change and delete your prompts in Prompt share':
      'Prompt share’de prompt’larınızı oluşturma, değiştirme ve silme',
    'Created new recovery codes': 'Yeni kurtarma kodları oluşturdu',
    'Created when you add your first passkey or app.':
      'İlk geçiş anahtarınızı veya uygulamanızı eklediğinizde oluşturulur.',
    'Created {0}': '{0} tarihinde oluşturuldu',
    'Created {0}.': '{0} tarihinde oluşturuldu.',
    'Credentials for a service that checks tokens at <0/> (RFC 7662) instead of a Service Binding. Each sees only tokens issued for its own resource.':
      'Token’ları bir Service Binding yerine <0/> adresinde (RFC 7662) denetleyen bir hizmet için kimlik bilgileri. Her biri yalnızca kendi kaynağı için verilen token’ları görür.',
    'Data downloaded': 'Veriler indirildi',
    'Database backups, for up to 30 days, used only to recover from failures':
      'Yalnızca arızalardan kurtulmak için kullanılan, 30 güne kadar saklanan veritabanı yedekleri',
    Deactivate: 'Devre dışı bırak',
    'Deactivated by its organization': 'Kurumu tarafından devre dışı bırakıldı',
    Decline: 'Reddet',
    Delete: 'Sil',
    'Delete account': 'Hesabı sil',
    'Delete account…': 'Hesabı sil…',
    'Delete my account': 'Hesabımı sil',
    'Delete organization': 'Kurumu sil',
    'Delete organization…': 'Kurumu sil…',
    'Delete your 2earl account': '2earl hesabınızı silin',
    'Delete your account': 'Hesabınızı silin',
    'Delete {0} and disconnect their apps. This can’t be undone.':
      '{0} hesabını sil ve uygulamalarının bağlantısını kes. Bu geri alınamaz.',
    'Delete {0}, its memberships and invitations. Members keep their accounts. This can’t be undone.':
      '{0} kurumunu, üyeliklerini ve davetlerini sil. Üyeler hesaplarını korur. Bu geri alınamaz.',
    'Delete {0}’s account': '{0} hesabını sil',
    'Delete “{0}”': '“{0}” kurumunu sil',
    'Deleted accounts whose data a service hasn’t confirmed deleting yet. Delivery retries every 15 minutes':
      'Verilerinin silindiğini bir hizmetin henüz onaylamadığı silinmiş hesaplar. Gönderim her 15 dakikada bir yeniden denenir',
    'Deleted accounts whose data a service hasn’t confirmed deleting yet. Delivery retries every 15 minutes.':
      'Verilerinin silindiğini bir hizmetin henüz onaylamadığı silinmiş hesaplar. Gönderim her 15 dakikada bir yeniden denenir.',
    'Deleted now': 'Şimdi silinir',
    'Deletes the organization, its memberships and invitations, for everyone. Members keep their own accounts.':
      'Kurumu, üyeliklerini ve davetlerini herkes için siler. Üyeler kendi hesaplarını korur.',
    'Delete…': 'Sil…',
    'Deletion delivered to a service': 'Silme bir hizmete iletildi',
    'Deletion didn’t finish': 'Silme tamamlanmadı',
    'Deletion notices waiting': 'Bekleyen silme bildirimleri',
    'Deletion stopped': 'Silme durduruldu',
    Deny: 'Reddet',
    'Desktop client': 'Masaüstü istemcisi',
    Detail: 'Ayrıntı',
    Developers: 'Geliştiriciler',
    Devices: 'Cihazlar',
    'Didn’t get it?': 'Gelmedi mi?',
    'Directory added a member': 'Dizin bir üye ekledi',
    'Directory changed a group': 'Dizin bir grubu değiştirdi',
    'Directory changed a role': 'Dizin bir rolü değiştirdi',
    'Directory created a group': 'Dizin bir grup oluşturdu',
    'Directory created a managed account': 'Dizin yönetilen bir hesap oluşturdu',
    'Directory deactivated an account': 'Dizin bir hesabı devre dışı bıraktı',
    'Directory deleted a group': 'Dizin bir grubu sildi',
    'Directory provisioned a user': 'Dizin bir kullanıcı ekledi',
    'Directory reactivated an account': 'Dizin bir hesabı yeniden etkinleştirdi',
    'Directory removed a member': 'Dizin bir üyeyi çıkardı',
    'Directory removed a user': 'Dizin bir kullanıcıyı kaldırdı',
    'Directory scheduled an account deletion': 'Dizin bir hesap silme planladı',
    'Directory sync': 'Dizin eşitlemesi',
    'Directory sync (SCIM 2.0)': 'Dizin eşitlemesi (SCIM 2.0)',
    'Directory sync token created': 'Dizin eşitleme token’ı oluşturuldu',
    'Directory sync token revoked': 'Dizin eşitleme token’ı iptal edildi',
    'Directory updated a user': 'Dizin bir kullanıcıyı güncelledi',
    Disconnect: 'Bağlantıyı kes',
    'Disconnect {0}': '{0} bağlantısını kes',
    'Disconnected an app': 'Bir uygulamanın bağlantısını kesti',
    'Disconnected {0}': '{0} bağlantısını kesti',
    'Discovery:': 'Keşif:',
    Does: 'Yapar',
    Domain: 'Alan adı',
    'Domain added. Publish the TXT record, then check it':
      'Alan adı eklendi. TXT kaydını yayımlayın, ardından denetleyin',
    'Domain added. Publish the TXT record, then check it.':
      'Alan adı eklendi. TXT kaydını yayımlayın, ardından denetleyin.',
    'Domain removed': 'Alan adı kaldırıldı',
    'Domain removed.': 'Alan adı kaldırıldı.',
    'Domain verified': 'Alan adı doğrulandı',
    'Domain verified.': 'Alan adı doğrulandı.',
    Domains: 'Alan adları',
    'Domains & SSO': 'Alan adları ve SSO',
    'Domains &amp; SSO': 'Alan adları ve SSO',
    'Domains and directory sync': 'Alan adları ve dizin eşitlemesi',
    Done: 'Tamam',
    'Don’t ask again for this app for 30 days': 'Bu uygulama için 30 gün boyunca yeniden sorma',
    'Download a copy': 'Bir kopyasını indirin',
    'Download the log': 'Kaydı indirin',
    'Download your data': 'Verilerinizi indirin',
    'Downloaded your data': 'Verilerinizi indirdi',
    'Edge on Android': 'Android üzerinde Edge',
    'Edge on ChromeOS': 'ChromeOS üzerinde Edge',
    'Edge on Linux': 'Linux üzerinde Edge',
    'Edge on Windows': 'Windows üzerinde Edge',
    'Edge on iPad': 'iPad üzerinde Edge',
    'Edge on iPhone': 'iPhone üzerinde Edge',
    'Edge on macOS': 'macOS üzerinde Edge',
    'Email address': 'E-posta adresi',
    'Email address of an existing account': 'Mevcut bir hesabın e-posta adresi',
    'Email code': 'E-posta kodu',
    'Email code not sent (limit)': 'E-posta kodu gönderilmedi (sınır)',
    'Email code sent': 'E-posta kodu gönderildi',
    'Endpoint URL': 'Uç nokta URL’si',
    'Enter 1 to 10 redirect URIs, one per line: https, or http on localhost, 127.0.0.1 or [::1], without a fragment.':
      'Her satıra bir tane olmak üzere 1 ile 10 arasında yönlendirme URI’si girin: https ya da localhost, 127.0.0.1 veya [::1] üzerinde http, parça (#) olmadan.',
    'Enter a client ID': 'Bir istemci kimliği girin',
    'Enter a client ID.': 'Bir istemci kimliği girin.',
    'Enter a domain name, such as example.com': 'example.com gibi bir alan adı girin',
    'Enter a domain name, such as example.com.': 'example.com gibi bir alan adı girin.',
    'Enter a name for the resource server': 'Kaynak sunucusu için bir ad girin',
    'Enter a name for the resource server.': 'Kaynak sunucusu için bir ad girin.',
    'Enter a valid email address.': 'Geçerli bir e-posta adresi girin.',
    'Enter an email address like name@example.com.': 'ad@ornek.com gibi bir e-posta adresi girin.',
    'Enter an https URL.': 'Bir https URL’si girin.',
    'Enter one email address': 'Tek bir e-posta adresi girin',
    'Enter one email address.': 'Tek bir e-posta adresi girin.',
    'Enter the app’s client ID': 'Uygulamanın istemci kimliğini girin',
    'Enter the app’s client ID.': 'Uygulamanın istemci kimliğini girin.',
    'Enter the app’s name': 'Uygulamanın adını girin',
    'Enter the app’s name.': 'Uygulamanın adını girin.',
    'Enter the code your device shows, for example the 2earl command-line tool in your terminal.':
      'Cihazınızın gösterdiği kodu girin; örneğin terminalinizdeki 2earl komut satırı aracının gösterdiği kod.',
    'Enter the date the client secret expires, or leave it empty.':
      'İstemci sırrının bitiş tarihini girin ya da boş bırakın.',
    'Enter the identity provider’s metadata URL, or its entity ID, an https sign-in URL and its signing certificate.':
      'Kimlik sağlayıcının meta veri URL’sini ya da varlık kimliğini, bir https giriş URL’sini ve imzalama sertifikasını girin.',
    'Enter the provider’s https issuer URL, the client ID and the client secret.':
      'Sağlayıcının https yayıncı (issuer) URL’sini, istemci kimliğini ve istemci sırrını girin.',
    'Enter this code to add this address to your 2earl account. It works once, for 10 minutes.':
      'Bu adresi 2earl hesabınıza eklemek için bu kodu girin. Bir kez ve 10 dakika boyunca çalışır.',
    'Enter this code to add this address to your 2earl account:':
      'Bu adresi 2earl hesabınıza eklemek için bu kodu girin:',
    'Enter this code to confirm deleting your 2earl account. It works once, for 10 minutes.':
      '2earl hesabınızı silmeyi onaylamak için bu kodu girin. Bir kez ve 10 dakika boyunca çalışır.',
    'Enter this code to confirm deleting your 2earl account:':
      '2earl hesabınızı silmeyi onaylamak için bu kodu girin:',
    'Enter this code to sign in to 2earl, or to create your account. It works once, for 10 minutes.':
      '2earl’e giriş yapmak ya da hesabınızı oluşturmak için bu kodu girin. Bir kez ve 10 dakika boyunca çalışır.',
    'Enter this code to sign in to 2earl, or to create your account:':
      '2earl’e giriş yapmak ya da hesabınızı oluşturmak için bu kodu girin:',
    'Enter your work email address': 'İş e-posta adresinizi girin',
    'Enter your work email address.': 'İş e-posta adresinizi girin.',
    'Entity ID': 'Varlık kimliği (Entity ID)',
    'Entra ID: https://login.microsoftonline.com/&lt;tenant ID&gt;/v2.0 · Google Workspace: https://accounts.google.com · Okta: https://&lt;your domain&gt;.okta.com':
      'Entra ID: https://login.microsoftonline.com/&lt;kiracı kimliği&gt;/v2.0 · Google Workspace: https://accounts.google.com · Okta: https://&lt;alan adınız&gt;.okta.com',
    'Entra ID: the application’s “Sign on URL”. Okta: “Initiate login URI”, or a bookmark app. It starts sign-in through your provider, so the 2earl tile in My Apps or the Okta dashboard works.':
      'Entra ID: uygulamanın “Sign on URL” alanı. Okta: “Initiate login URI” ya da bir yer imi uygulaması. Girişi sağlayıcınız üzerinden başlatır; böylece My Apps’teki veya Okta panosundaki 2earl kutucuğu çalışır.',
    'Entra ID: “App Federation Metadata Url”. Okta: “Metadata URL” on the Sign On tab. 2earl reads the fields below from it, and again every day, so new signing certificates arrive by themselves. Leave it empty to enter them by hand.':
      'Entra ID: “App Federation Metadata Url”. Okta: Sign On sekmesindeki “Metadata URL”. 2earl aşağıdaki alanları buradan ve her gün yeniden okur; böylece yeni imzalama sertifikaları kendiliğinden gelir. Alanları elle girmek için boş bırakın.',
    'Entra ID: “App Federation Metadata Url”. Okta: “Metadata URL” on the Sign On tab. 2earl reads the fields below from it, and again every day, so new signing certificates arrive by themselves. Leave it empty to enter them by hand. <0>{0}</0>':
      'Entra ID: “App Federation Metadata Url”. Okta: Sign On sekmesindeki “Metadata URL”. 2earl aşağıdaki alanları buradan ve her gün yeniden okur; böylece yeni imzalama sertifikaları kendiliğinden gelir. Alanları elle girmek için boş bırakın. <0>{0}</0>',
    'Entra ID’s secrets expire. Owners get an email 30, 7 and 1 days before.':
      'Entra ID sırlarının süresi dolar. Sahipler 30, 7 ve 1 gün önce e-posta alır.',
    'Error on our side': 'Bizim tarafımızda bir hata oluştu',
    Event: 'Olay',
    'Every browser where your 2earl account is signed in. If you don’t recognise one, sign it out, then check how you sign in and add a second factor.':
      '2earl hesabınızın açık olduğu her tarayıcı. Tanımadığınız biri varsa oturumunu kapatın, ardından nasıl giriş yaptığınızı denetleyin ve ikinci bir doğrulama adımı ekleyin.',
    "Every change is in the organization's activity, with <0/> and the key's ID.":
      'Her değişiklik, <0/> ve anahtarın kimliğiyle birlikte kurumun etkinlik kaydındadır.',
    'Every event, not only the latest 200, with times, people, apps and network prefixes. The log keeps 90 days; download it or stream it to keep it longer.':
      'Yalnızca son 200 olay değil, her olay; zamanları, kişileri, uygulamaları ve ağ önekleriyle. Kayıt 90 gün tutulur; daha uzun saklamak için indirin ya da akışla aktarın.',
    'Every other device is signed out': 'Diğer tüm cihazların oturumu kapatıldı',
    'Every other device is signed out.': 'Diğer tüm cihazların oturumu kapatıldı.',
    'Every owner gets these emails, including the one who made the change.':
      'Değişikliği yapan da dahil her sahip bu e-postaları alır.',
    'Every signed-in browser, including this one': 'Bu dahil, oturum açık her tarayıcı',
    Everyone: 'Herkes',
    'Everything your account holds is yours to take with you or to delete.':
      'Hesabınızdaki her şey sizindir: yanınızda götürebilir ya da silebilirsiniz.',
    Expired: 'Süresi doldu',
    'Expires {0}': 'Bitiş {0}',
    'Failing: the last delivery was refused ({0}). Retrying, nothing is skipped':
      'Başarısız: son gönderim reddedildi ({0}). Yeniden deneniyor, hiçbir şey atlanmıyor',
    'Failing: the last delivery was refused ({0}). Retrying, nothing is skipped.':
      'Başarısız: son gönderim reddedildi ({0}). Yeniden deneniyor, hiçbir şey atlanmıyor.',
    Filter: 'Filtrele',
    Find: 'Bul',
    'Find by email address or name': 'E-posta adresi veya ada göre bulun',
    'Firefox on Android': 'Android üzerinde Firefox',
    'Firefox on ChromeOS': 'ChromeOS üzerinde Firefox',
    'Firefox on Linux': 'Linux üzerinde Firefox',
    'Firefox on Windows': 'Windows üzerinde Firefox',
    'Firefox on iPad': 'iPad üzerinde Firefox',
    'Firefox on iPhone': 'iPhone üzerinde Firefox',
    'Firefox on macOS': 'macOS üzerinde Firefox',
    First: 'İlk',
    For: 'Kimin için',
    "For an organization's own scripts: HR syncs, offboarding tools, log collectors. Owners create keys on the organization's <0>Settings</0> page. A key is shown once; 2earl keeps only its SHA-256.":
      'Bir kurumun kendi betikleri için: İK eşitlemeleri, işten ayrılma araçları, kayıt toplayıcılar. Sahipler anahtarları kurumun <0>Ayarlar</0> sayfasında oluşturur. Bir anahtar bir kez gösterilir; 2earl yalnızca SHA-256 özetini saklar.',
    'For apps that can’t publish a client metadata document. Public clients only: they use PKCE and have no secret.':
      'İstemci meta veri belgesi yayımlayamayan uygulamalar için. Yalnızca açık istemciler: PKCE kullanırlar ve sırları yoktur.',
    'For the accounts you manage. Owners keep every way in and every network, so a broken identity provider or a new office network can’t lock you out; the second-factor rules and the session length apply to them too.':
      'Yönettiğiniz hesaplar için. Sahipler her giriş yolunu ve her ağı korur; böylece bozuk bir kimlik sağlayıcı ya da yeni bir ofis ağı sizi dışarıda bırakamaz. İkinci doğrulama adımı kuralları ve oturum süresi onlar için de geçerlidir.',
    'For your own scripts: read members, domains and the audit log, and with a read-and-write key change roles, deactivate and reactivate managed accounts, and remove members. The API never acts on owners. Base URL <0/>; see <1>the API reference</1>.':
      'Kendi betikleriniz için: üyeleri, alan adlarını ve denetim kaydını okuyun; okuma ve yazma anahtarıyla rolleri değiştirin, yönetilen hesapları devre dışı bırakıp yeniden etkinleştirin ve üyeleri çıkarın. API sahipler üzerinde asla işlem yapmaz. Temel URL <0/>; <1>API başvurusuna</1> bakın.',
    'For your safety, the link works only in the browser where you asked for the code. Go back to that browser and open the link there, or type the 6-digit code from the email.':
      'Güvenliğiniz için bağlantı yalnızca kodu istediğiniz tarayıcıda çalışır. O tarayıcıya dönüp bağlantıyı orada açın ya da e-postadaki 6 haneli kodu yazın.',
    'From your directory': 'Dizininizden',
    'Get a new code': 'Yeni kod al',
    'Give the key a name': 'Anahtara bir ad verin',
    'Give the key a name.': 'Anahtara bir ad verin.',
    'Go back to your device: it continues on its own in a few seconds. You can close this page.':
      'Cihazınıza dönün: birkaç saniye içinde kendiliğinden devam eder. Bu sayfayı kapatabilirsiniz.',
    'Go to 2earl.com': '2earl.com’a git',
    'Go to your account': 'Hesabınıza gidin',
    Google: 'Google',
    'Google and email code': 'Google ve e-posta kodu',
    'Google didn’t confirm it was you: the request expired, was cancelled, or you signed out in between. Nothing was deleted.':
      'Google kimliğinizi doğrulamadı: istek süresi doldu, iptal edildi ya da arada çıkış yaptınız. Hiçbir şey silinmedi.',
    'Google still lists 2earl among the apps you signed in to. You can remove it in your Google Account under Security → Your connections to third-party apps &amp; services.':
      'Google, 2earl’ü hâlâ giriş yaptığınız uygulamalar arasında gösteriyor. Google Hesabınızda Güvenlik → Üçüncü taraf uygulamalar ve hizmetlerle bağlantılarınız bölümünden kaldırabilirsiniz.',
    'Google will ask you to choose your account. Choose the one you sign in to 2earl with.':
      'Google sizden hesabınızı seçmenizi isteyecek. 2earl’e giriş yaptığınız hesabı seçin.',
    'Groups and roles': 'Gruplar ve roller',
    'Groups your directory sends appear here. Give a group the admin or auditor role, and your directory decides who has it.':
      'Dizininizin gönderdiği gruplar burada görünür. Bir gruba yönetici ya da denetçi rolünü verin; kimin bu role sahip olacağına dizininiz karar verir.',
    'How you sign in': 'Nasıl giriş yaptığınız',
    'I understand my account and connected apps can’t be restored.':
      'Hesabımın ve bağlı uygulamalarımın geri getirilemeyeceğini anlıyorum.',
    'I want to delete this account and its data for good.':
      'Bu hesabı ve verilerini kalıcı olarak silmek istiyorum.',
    'I want to leave this organization. Rejoining needs a new invitation.':
      'Bu kurumdan ayrılmak istiyorum. Yeniden katılmak için yeni bir davet gerekir.',
    'ID <0/>': 'Kimlik <0/>',
    'ID <0/> · for <1/>': 'Kimlik <0/> · kaynak <1/>',
    'ISO 8601 time: events at or after it': 'ISO 8601 zamanı: o andaki ve sonraki olaylar',
    'Identity provider entity ID (issuer)': 'Kimlik sağlayıcının varlık kimliği (issuer)',
    'If this wasn’t you, disconnect the app and review the devices signed in to your account.':
      'Bunu siz yapmadıysanız uygulamanın bağlantısını kesin ve hesabınızda oturumu açık cihazları gözden geçirin.',
    'If this wasn’t you, review how you sign in and the devices signed in to your account, and add a second factor.':
      'Bunu siz yapmadıysanız nasıl giriş yaptığınızı ve hesabınızda oturumu açık cihazları gözden geçirin ve ikinci bir doğrulama adımı ekleyin.',
    'If you can’t use your passkey or app, each of these codes lets you in once. This is the only time they’re shown.':
      'Geçiş anahtarınızı veya uygulamanızı kullanamazsanız bu kodların her biri sizi bir kez içeri alır. Kodlar yalnızca bu kez gösterilir.',
    'If you didn’t ask for it, you can ignore this email. Nobody can use it without access to your inbox.':
      'Bunu siz istemediyseniz bu e-postayı yok sayabilirsiniz. Gelen kutunuza erişimi olmayan kimse onu kullanamaz.',
    'If you didn’t ask to delete your account, sign in and add a second factor: someone may be using your account.':
      'Hesabınızı silmeyi siz istemediyseniz giriş yapın ve ikinci bir doğrulama adımı ekleyin: biri hesabınızı kullanıyor olabilir.',
    'If you or another owner expected this, there’s nothing to do. If not, check the organization’s activity, undo the change, and sign out the account that made it; an owner’s account can be secured from its own Security page.':
      'Bunu siz ya da başka bir sahip bekliyorduysanız yapılacak bir şey yok. Beklemiyorduysanız kurumun etkinliğine bakın, değişikliği geri alın ve değişikliği yapan hesabın oturumlarını kapatın; bir sahibin hesabı kendi Güvenlik sayfasından güvenceye alınabilir.',
    'If your organization connected its sign-in to 2earl, enter your work address and we’ll send you there.':
      'Kurumunuz giriş hizmetini 2earl’e bağladıysa iş adresinizi girin, sizi oraya yönlendirelim.',
    Imprint: 'Künye',
    'In use by your people': 'Kişileriniz tarafından kullanılıyor',
    Invitation: 'Davet',
    'Invitation added': 'Davet eklendi',
    'Invitation added.': 'Davet eklendi.',
    'Invitation declined': 'Davet reddedildi',
    'Invitation declined.': 'Davet reddedildi.',
    'Invitation removed': 'Davet kaldırıldı',
    'Invitation sent': 'Davet gönderildi',
    'Invitation sent again. It works for another 14 days':
      'Davet yeniden gönderildi. 14 gün daha geçerli',
    'Invitation sent again. It works for another 14 days.':
      'Davet yeniden gönderildi. 14 gün daha geçerli.',
    'Invitation sent.': 'Davet gönderildi.',
    'Invitation sent. It works for 14 days': 'Davet gönderildi. 14 gün boyunca geçerli',
    'Invitation sent. It works for 14 days.': 'Davet gönderildi. 14 gün boyunca geçerli.',
    'Invitation used': 'Davet kullanıldı',
    'Invitation withdrawn': 'Davet geri alındı',
    'Invitation withdrawn.': 'Davet geri alındı.',
    Invitations: 'Davetler',
    Invite: 'Davet et',
    'Invite an organization': 'Bir kurumu davet edin',
    'Invite by email address': 'E-posta adresiyle davet edin',
    'Invite people': 'Kişileri davet edin',
    Invited: 'Davet edildi',
    'Invited someone to set up an organization': 'Birini kurum kurmaya davet etti',
    'Invited to an organization': 'Bir kuruma davet edildi',
    'Invited {0}': '{0} tarihinde davet edildi',
    'Issuer URL': 'Yayıncı (issuer) URL’si',
    'It also asked for permissions 2earl doesn’t grant: <0/>. They will not be given.':
      '2earl’ün vermediği izinleri de istedi: <0/>. Bunlar verilmeyecek.',
    'It can deactivate or delete this account.': 'Bu hesabı devre dışı bırakabilir veya silebilir.',
    'It can require you to sign in through its single sign-on.':
      'Çoklu oturum açma hizmeti üzerinden giriş yapmanızı zorunlu tutabilir.',
    'It is asking only to know that you have a 2earl account':
      'Yalnızca bir 2earl hesabınız olduğunu bilmek istiyor',
    'It is asking only to know that you have a 2earl account.':
      'Yalnızca bir 2earl hesabınız olduğunu bilmek istiyor.',
    'It was already used, withdrawn or declined, or it expired after 7 days. Ask the person who invited you to send a new one.':
      'Zaten kullanılmış, geri alınmış veya reddedilmiş ya da 7 gün sonra süresi dolmuş. Sizi davet eden kişiden yeni bir davet göndermesini isteyin.',
    'It was used, withdrawn or has expired. If you still need an organization, ask 2earl to invite you again.':
      'Kullanılmış, geri alınmış ya da süresi dolmuş. Hâlâ bir kuruma ihtiyacınız varsa 2earl’den sizi yeniden davet etmesini isteyin.',
    'It will be able to': 'Şunları yapabilecek',
    'I’ve saved them': 'Kaydettim',
    'Join organization': 'Kuruma katıl',
    'Join {0}': '{0} kurumuna katılın',
    'Join “{0}”': '“{0}” kurumuna katılın',
    'Join “{0}” on 2earl': '2earl’de “{0}” kurumuna katılın',
    'Joined an organization': 'Bir kuruma katıldı',
    'Joined {0}': '{0} tarihinde katıldı',
    'Joiners get an account, leavers lose access at once (SCIM 2.0).':
      'Katılanlar bir hesap alır, ayrılanlar erişimini hemen kaybeder (SCIM 2.0).',
    'Keep account': 'Hesabı tut',
    'Keep it': 'Tut',
    'Keep it your own': 'Kendinize ait tutun',
    'Keep them in a password manager, or <0>download them as a text file</0>.':
      'Onları bir parola yöneticisinde saklayın ya da <0>metin dosyası olarak indirin</0>.',
    'Kept for a limited time': 'Sınırlı bir süre saklananlar',
    Key: 'Anahtar',
    'Key revoked. It stops working at once.': 'Anahtar iptal edildi. Hemen çalışmayı bırakır.',
    Language: 'Dil',
    'Last 30 days': 'Son 30 gün',
    'Last 7 days': 'Son 7 gün',
    'Last 90 days': 'Son 90 gün',
    'Last read recently': 'Kısa süre önce okundu',
    'Last read recently: {0}': 'Kısa süre önce okundu: {0}',
    'Last used {0}': 'Son kullanım {0}',
    Leave: 'Ayrıl',
    'Leave organization': 'Kurumdan ayrıl',
    'Left an organization': 'Bir kurumdan ayrıldı',
    'Let it manage my account': 'Hesabımı yönetmesine izin ver',
    'Let people sign in this way': 'Kişilerin bu şekilde giriş yapmasına izin ver',
    'Let people sign in this way (turns OpenID Connect off)':
      'Kişilerin bu şekilde giriş yapmasına izin ver (OpenID Connect’i kapatır)',
    'Let people sign in this way (turns SAML off)':
      'Kişilerin bu şekilde giriş yapmasına izin ver (SAML’i kapatır)',
    'Let the organization manage it': 'Kurumun yönetmesine izin verin',
    "Lifts the organization's deactivation": 'Kurumun devre dışı bırakmasını kaldırır',
    'Make admin': 'Yönetici yap',
    'Make auditor': 'Denetçi yap',
    'Make member': 'Üye yap',
    'Make owner': 'Sahip yap',
    'Make support': 'Destek yap',
    Manage: 'Yönet',
    'Manage accounts': 'Hesapları yönet',
    'Manage the 2earl accounts at a verified domain. New accounts there are managed from the start; people who already have one choose at their next sign-in, or keep it their own by removing the address. You can deactivate and delete managed accounts, and require your single sign-on. People can always download their data.':
      'Doğrulanmış bir alan adındaki 2earl hesaplarını yönetin. Oradaki yeni hesaplar baştan yönetilir; zaten hesabı olanlar bir sonraki girişlerinde seçim yapar ya da adresi kaldırarak hesabı kendilerine ait tutar. Yönetilen hesapları devre dışı bırakabilir, silebilir ve çoklu oturum açma hizmetinizi zorunlu tutabilirsiniz. Kişiler verilerini her zaman indirebilir.',
    'Manage the accounts at it': 'Oradaki hesapları yönetin',
    'Manage your own account on the account page.': 'Kendi hesabınızı hesap sayfasında yönetin.',
    Managed: 'Yönetilen',
    'Managed accounts': 'Yönetilen hesaplar',
    'Managed accounts can sign in any way again':
      'Yönetilen hesaplar yeniden her yolla giriş yapabilir',
    'Managed accounts can sign in any way again.':
      'Yönetilen hesaplar yeniden her yolla giriş yapabilir.',
    'Managed accounts may connect any app again':
      'Yönetilen hesaplar yeniden herhangi bir uygulamayı bağlayabilir',
    'Managed accounts may connect any app again.':
      'Yönetilen hesaplar yeniden herhangi bir uygulamayı bağlayabilir.',
    'Managed accounts may now use only the allowed apps':
      'Yönetilen hesaplar artık yalnızca izin verilen uygulamaları kullanabilir',
    'Managed accounts may now use only the allowed apps.':
      'Yönetilen hesaplar artık yalnızca izin verilen uygulamaları kullanabilir.',
    'Managed accounts now sign in only with single sign-on':
      'Yönetilen hesaplar artık yalnızca çoklu oturum açmayla giriş yapar',
    'Managed accounts now sign in only with single sign-on.':
      'Yönetilen hesaplar artık yalnızca çoklu oturum açmayla giriş yapar.',
    'Managed accounts released': 'Yönetilen hesaplar bırakıldı',
    'Managed accounts sign in only through your identity provider. Owners can still sign in other ways, so a broken identity provider can’t lock you out. Sessions started another way end at once.':
      'Yönetilen hesaplar yalnızca kimlik sağlayıcınız üzerinden giriş yapar. Sahipler başka yollarla da giriş yapabilir; böylece bozuk bir kimlik sağlayıcı sizi dışarıda bırakamaz. Başka bir yolla başlatılan oturumlar hemen sona erer.',
    'Managed by your organization': 'Kurumunuz tarafından yönetiliyor',
    'Managed by “{0}”: it can require its single sign-on, and deactivate or delete this account.':
      '“{0}” tarafından yönetiliyor: çoklu oturum açma hizmetini zorunlu tutabilir, bu hesabı devre dışı bırakabilir veya silebilir.',
    'Managed since {0}': '{0} tarihinden beri yönetiliyor',
    'Mark a group admin or auditor, and your directory decides who has that role. Owners never change':
      'Bir grubu yönetici ya da denetçi olarak işaretleyin; o role kimin sahip olacağına dizininiz karar verir. Sahipler asla değişmez',
    'Mark a group admin or auditor, and your directory decides who has that role. Owners never change.':
      'Bir grubu yönetici ya da denetçi olarak işaretleyin; o role kimin sahip olacağına dizininiz karar verir. Sahipler asla değişmez.',
    'Mark as verified': 'Doğrulanmış olarak işaretle',
    Meaning: 'Anlamı',
    Member: 'Üye',
    'Member removed': 'Üye çıkarıldı',
    'Member removed.': 'Üye çıkarıldı.',
    'Member since {0}': '{0} tarihinden beri üye',
    Members: 'Üyeler',
    'Members <0>{0}</0>': 'Üyeler <0>{0}</0>',
    'Members can see who else is in the organization. Everyone here sees each member’s name and email address.':
      'Üyeler kurumda başka kimlerin olduğunu görebilir. Buradaki herkes her üyenin adını ve e-posta adresini görür.',
    'Members of the organization will see your name and email address, and you’ll see theirs. Your account stays yours: you can leave at any time.':
      'Kurumun üyeleri adınızı ve e-posta adresinizi görecek, siz de onlarınkini göreceksiniz. Hesabınız size ait kalır: istediğiniz zaman ayrılabilirsiniz.',
    Metadata: 'Meta veri',
    'Metadata URL (recommended)': 'Meta veri URL’si (önerilir)',
    'Microsoft Entra ID, Okta and other directories provision people and groups into the organization. Owners create a token on <0>Domains &amp; SSO</0>, after verifying a domain.':
      'Microsoft Entra ID, Okta ve diğer dizinler kişileri ve grupları kuruma ekler. Sahipler bir alan adını doğruladıktan sonra <0>Alan adları ve SSO</0> sayfasında bir token oluşturur.',
    Name: 'Ad',
    'Name (optional)': 'Ad (isteğe bağlı)',
    'Name ID': 'Name ID',
    Network: 'Ağ',
    'Network prefixes are shortened IP addresses (/24 for IPv4, /48 for IPv6). Full IP addresses are never stored':
      'Ağ önekleri kısaltılmış IP adresleridir (IPv4 için /24, IPv6 için /48). Tam IP adresleri asla saklanmaz',
    'Network prefixes are shortened IP addresses (/24 for IPv4, /48 for IPv6). Full IP addresses are never stored.':
      'Ağ önekleri kısaltılmış IP adresleridir (IPv4 için /24, IPv6 için /48). Tam IP adresleri asla saklanmaz.',
    'New events are sent within a minute to an https endpoint of yours that accepts JSON (for example a small relay in front of Splunk, Datadog or Microsoft Sentinel), in batches of up to 500, each signed. Failed deliveries are retried until they’re accepted.':
      'Yeni olaylar bir dakika içinde, JSON kabul eden bir https uç noktanıza (örneğin Splunk, Datadog veya Microsoft Sentinel önündeki küçük bir aktarıcı) her biri imzalı, en fazla 500’lük gruplar halinde gönderilir. Başarısız gönderimler kabul edilene kadar yeniden denenir.',
    'New here? The same buttons create your account. With email, there’s no password: we send you a code each time.':
      'Yeni misiniz? Aynı düğmeler hesabınızı da oluşturur. E-postayla parola yoktur: her seferinde size bir kod göndeririz.',
    'New recovery codes for your 2earl account': '2earl hesabınız için yeni kurtarma kodları',
    'New recovery codes were created': 'Yeni kurtarma kodları oluşturuldu',
    'New recovery codes were created for your 2earl account. The earlier ones no longer work':
      '2earl hesabınız için yeni kurtarma kodları oluşturuldu. Öncekiler artık çalışmıyor',
    'New recovery codes were created for your 2earl account. The earlier ones no longer work.':
      '2earl hesabınız için yeni kurtarma kodları oluşturuldu. Öncekiler artık çalışmıyor.',
    'New role for {0}': '{0} için yeni rol',
    'New secret': 'Yeni sır',
    'Next signing certificate (optional)': 'Sonraki imzalama sertifikası (isteğe bağlı)',
    'Next signing certificate (optional) <0>Expires {0}</0>':
      'Sonraki imzalama sertifikası (isteğe bağlı) <0>Bitiş {0}</0>',
    'No 2earl account signs in with that address. Ask them to create one first (add a sign-up invitation if sign-up is closed).':
      'Bu adresle giriş yapan bir 2earl hesabı yok. Önce bir hesap oluşturmalarını isteyin (kayıt kapalıysa bir kayıt daveti ekleyin).',
    'No account matches': 'Eşleşen hesap yok',
    'No account matches.': 'Eşleşen hesap yok.',
    'No app with that client ID has registered with 2earl.':
      'Bu istemci kimliğiyle 2earl’e kayıtlı bir uygulama yok.',
    'No app with that client ID: it isn’t registered, and no valid metadata document could be fetched from it.':
      'Bu istemci kimliğine sahip bir uygulama yok: kayıtlı değil ve ondan geçerli bir meta veri belgesi alınamadı.',
    'No apps allowed yet.': 'Henüz izin verilen uygulama yok.',
    'No apps are connected. When you allow an app to act for you, it appears here and you can disconnect it at any time.':
      'Bağlı uygulama yok. Bir uygulamanın sizin adınıza işlem yapmasına izin verdiğinizde burada görünür ve bağlantısını istediğiniz zaman kesebilirsiniz.',
    'No code sent': 'Kod gönderilmedi',
    'No domains.': 'Alan adı yok.',
    'No invitations yet.': 'Henüz davet yok.',
    'No organization given': 'Kurum belirtilmedi',
    'No organization given.': 'Kurum belirtilmedi.',
    'No organization signs in this address with single sign-on. Sign in another way.':
      'Bu adresle çoklu oturum açma kullanan bir kurum yok. Başka bir yolla giriş yapın.',
    'No organizations yet.': 'Henüz kurum yok.',
    'No passkey on this account': 'Bu hesapta geçiş anahtarı yok',
    'No passkey on this account.': 'Bu hesapta geçiş anahtarı yok.',
    'No passkeys yet.': 'Henüz geçiş anahtarı yok.',
    'No registered apps.': 'Kayıtlı uygulama yok.',
    'No resource servers.': 'Kaynak sunucusu yok.',
    'No staff besides you.': 'Sizden başka ekip üyesi yok.',
    'No user given': 'Kullanıcı belirtilmedi',
    'No user given.': 'Kullanıcı belirtilmedi.',
    'No verified apps.': 'Doğrulanmış uygulama yok.',
    None: 'Yok',
    'Not a registered app': 'Kayıtlı bir uygulama değil',
    'Not a registered app.': 'Kayıtlı bir uygulama değil.',
    'Not deleted': 'Silinmez',
    'Not from this network': 'Bu ağdan olmaz',
    'Not managed: accounts there belong to their people':
      'Yönetilmiyor: oradaki hesaplar sahiplerine ait',
    'Not now': 'Şimdi değil',
    'Not set up': 'Kurulmadı',
    'Not signed in': 'Giriş yapılmadı',
    'Not verified': 'Doğrulanmadı',
    'Note (optional)': 'Not (isteğe bağlı)',
    'Nothing changed': 'Hiçbir şey değişmedi',
    'Nothing changed: an organization always keeps at least one owner':
      'Hiçbir şey değişmedi: bir kurumun her zaman en az bir sahibi olur',
    'Nothing changed: an organization always keeps at least one owner.':
      'Hiçbir şey değişmedi: bir kurumun her zaman en az bir sahibi olur.',
    'Nothing changes until you choose.': 'Siz seçene kadar hiçbir şey değişmez.',
    'Nothing was added': 'Hiçbir şey eklenmedi',
    'Nothing was approved': 'Hiçbir şey onaylanmadı',
    'Nothing yet.': 'Henüz bir şey yok.',
    'Nothing yet. Invitations, role changes, members joining and leaving, directory changes, and the sign-ins of accounts you manage appear here.':
      'Henüz bir şey yok. Davetler, rol değişiklikleri, katılan ve ayrılan üyeler, dizin değişiklikleri ve yönettiğiniz hesapların girişleri burada görünür.',
    'Nothing you did caused this. Try again in a moment; if it keeps happening, write to us with the reference below.':
      'Buna sizin yaptığınız bir şey neden olmadı. Biraz sonra yeniden deneyin; devam ederse aşağıdaki referansla bize yazın.',
    Off: 'Kapalı',
    'Off: managed accounts may connect any app.':
      'Kapalı: yönetilen hesaplar herhangi bir uygulamayı bağlayabilir.',
    'On, with OpenID Connect': 'Açık, OpenID Connect ile',
    'On, with SAML 2.0': 'Açık, SAML 2.0 ile',
    'One 2earl account for every 2earl service, and one place to decide which apps may act for you.':
      'Her 2earl hizmeti için tek bir 2earl hesabı ve sizin adınıza hangi uygulamaların işlem yapabileceğine karar verdiğiniz tek bir yer.',
    'One JSON file with your profile, sign-in methods, devices, connected apps, organizations and security events, and what 2earl services hold about you.':
      'Profiliniz, giriş yöntemleriniz, cihazlarınız, bağlı uygulamalarınız, kurumlarınız ve güvenlik olaylarınızla 2earl hizmetlerinin hakkınızda tuttuklarını içeren tek bir JSON dosyası.',
    'One account for every 2earl service.': 'Her 2earl hizmeti için tek hesap.',
    'One more step': 'Bir adım daha',
    'One range per line (IPv4 or IPv6, CIDR), up to 50. Empty: anywhere. Apps that people connected keep working elsewhere.':
      'Her satıra bir aralık (IPv4 veya IPv6, CIDR), en fazla 50. Boş: her yerden. Kişilerin bağladığı uygulamalar başka yerlerde çalışmaya devam eder.',
    'Only allow the apps below': 'Yalnızca aşağıdaki uygulamalara izin ver',
    'Only continue if you started this yourself, on a device in front of you. 2earl never asks you for this code by email, chat or phone.':
      'Yalnızca bunu kendiniz, önünüzdeki bir cihazda başlattıysanız devam edin. 2earl bu kodu sizden asla e-postayla, sohbetle ya da telefonla istemez.',
    'Only owners and admins can invite people.':
      'Yalnızca sahipler ve yöneticiler kişileri davet edebilir.',
    'Only owners and admins can withdraw invitations':
      'Davetleri yalnızca sahipler ve yöneticiler geri alabilir',
    'Only owners and admins can withdraw invitations.':
      'Davetleri yalnızca sahipler ve yöneticiler geri alabilir.',
    'Only owners can act on owners': 'Sahipler üzerinde yalnızca sahipler işlem yapabilir',
    'Only owners can act on owners.': 'Sahipler üzerinde yalnızca sahipler işlem yapabilir.',
    'Only owners can delete the organization.': 'Kurumu yalnızca sahipler silebilir.',
    'Only owners can make or change owners.':
      'Sahipleri yalnızca sahipler belirleyebilir veya değiştirebilir.',
    'Only owners can remove owners.': 'Sahipleri yalnızca sahipler çıkarabilir.',
    'Only owners can rename the organization.': 'Kurumun adını yalnızca sahipler değiştirebilir.',
    'Only the owner changes the owner’s account.': 'Sahibin hesabını yalnızca sahip değiştirir.',
    'Open Domains & SSO': 'Alan adları ve SSO’yu açın',
    'Open invitations': 'Açık davetler',
    'Open sign-up': 'Açık kayıt',
    'Open the activity': 'Etkinliği açın',
    'Open the admin pages': 'Yönetim sayfalarını açın',
    'Open the invitation': 'Daveti açın',
    'Open the invitation and sign in with this email address to accept or decline it.':
      'Daveti açın ve kabul etmek ya da reddetmek için bu e-posta adresiyle giriş yapın.',
    'Open the invitation, then sign in with this email address, or create your account with it. You choose the organization’s name.':
      'Daveti açın, ardından bu e-posta adresiyle giriş yapın ya da onunla hesabınızı oluşturun. Kurumun adını siz seçersiniz.',
    'Open the link where you asked for it': 'Bağlantıyı istediğiniz yerde açın',
    'Open your organizations': 'Kurumlarınızı açın',
    'OpenID Connect: Microsoft Entra ID, Google Workspace, Okta and others':
      'OpenID Connect: Microsoft Entra ID, Google Workspace, Okta ve diğerleri',
    'Opera on Android': 'Android üzerinde Opera',
    'Opera on ChromeOS': 'ChromeOS üzerinde Opera',
    'Opera on Linux': 'Linux üzerinde Opera',
    'Opera on Windows': 'Windows üzerinde Opera',
    'Opera on iPad': 'iPad üzerinde Opera',
    'Opera on iPhone': 'iPhone üzerinde Opera',
    'Opera on macOS': 'macOS üzerinde Opera',
    'Or paste this address into your browser:': 'Ya da bu adresi tarayıcınıza yapıştırın:',
    Organization: 'Kurum',
    'Organization allowed an app': 'Kurum bir uygulamaya izin verdi',
    'Organization changed its audit stream': 'Kurum denetim akışını değiştirdi',
    'Organization changed its security rules': 'Kurum güvenlik kurallarını değiştirdi',
    'Organization changed required SSO': 'Kurum zorunlu SSO ayarını değiştirdi',
    'Organization changed which apps its accounts may use':
      'Kurum hesaplarının kullanabileceği uygulamaları değiştirdi',
    'Organization created': 'Kurum oluşturuldu',
    'Organization created an API key': 'Kurum bir API anahtarı oluşturdu',
    'Organization created. Invite people below.':
      'Kurum oluşturuldu. Aşağıdan kişileri davet edin.',
    'Organization deactivated an account': 'Kurum bir hesabı devre dışı bıraktı',
    'Organization deleted': 'Kurum silindi',
    'Organization deleted an account': 'Kurum bir hesabı sildi',
    'Organization deleted by admin': 'Kurum yönetici tarafından silindi',
    'Organization deleted.': 'Kurum silindi.',
    'Organization deletion delivered to a service': 'Kurum silme bir hizmete iletildi',
    'Organization domain added': 'Kurum alan adı eklendi',
    'Organization domain removed': 'Kurum alan adı kaldırıldı',
    'Organization domain verified': 'Kurum alan adı doğrulandı',
    'Organization downloaded its audit log': 'Kurum denetim kaydını indirdi',
    'Organization gave a directory group a role': 'Kurum bir dizin grubuna rol verdi',
    'Organization invitation declined': 'Kurum daveti reddedildi',
    'Organization invitation withdrawn': 'Kurum daveti geri alındı',
    'Organization manages a domain': 'Kurum bir alan adını yönetiyor',
    'Organization name': 'Kurum adı',
    'Organization name (optional; they can change it)':
      'Kurum adı (isteğe bağlı; değiştirebilirler)',
    'Organization opened by staff': 'Kurum ekip tarafından açıldı',
    'Organization reactivated': 'Kurum yeniden etkinleştirildi',
    'Organization reactivated an account': 'Kurum bir hesabı yeniden etkinleştirdi',
    'Organization reactivated.': 'Kurum yeniden etkinleştirildi.',
    'Organization removed an allowed app': 'Kurum izin verilen bir uygulamayı kaldırdı',
    'Organization renamed.': 'Kurumun adı değiştirildi.',
    'Organization revoked an API key': 'Kurum bir API anahtarını iptal etti',
    'Organization role changed': 'Kurum rolü değişti',
    'Organization saved OpenID Connect sign-on': 'Kurum OpenID Connect girişini kaydetti',
    'Organization setup invitation sent again': 'Kurum kurulum daveti yeniden gönderildi',
    'Organization setup invitation withdrawn': 'Kurum kurulum daveti geri alındı',
    'Organization signed an account out everywhere':
      'Kurum bir hesabın her yerdeki oturumunu kapattı',
    'Organization stopped managing a domain': 'Kurum bir alan adını yönetmeyi bıraktı',
    'Organization suspended': 'Kurum askıya alındı',
    'Organization suspended.': 'Kurum askıya alındı.',
    Organizations: 'Kurumlar',
    'Organizations are set up by invitation': 'Kurumlar davetle kurulur',
    'Organizations are set up by invitation. The person you invite signs in with the address (or creates an account with it), names the organization and becomes its owner: its top admin, who adds the other admins and members.':
      'Kurumlar davetle kurulur. Davet ettiğiniz kişi o adresle giriş yapar (ya da onunla hesap oluşturur), kuruma bir ad verir ve sahibi olur: diğer yöneticileri ve üyeleri ekleyen en üst yönetici.',
    Other: 'Diğer',
    Overview: 'Genel bakış',
    Owner: 'Sahip',
    'Owners and admins of 2earl invite organizations. You can send an invitation that is still waiting again.':
      'Kurumları 2earl’ün sahibi ve yöneticileri davet eder. Hâlâ bekleyen bir daveti yeniden gönderebilirsiniz.',
    'Owners can do everything, including renaming and deleting the organization. Everyone here sees each member’s name and email address.':
      'Sahipler, kurumun adını değiştirmek ve kurumu silmek dahil her şeyi yapabilir. Buradaki herkes her üyenin adını ve e-posta adresini görür.',
    'Owners warned that SSO credentials expire':
      'Sahiplere SSO kimlik bilgilerinin süresinin dolacağı bildirildi',
    'Page not found': 'Sayfa bulunamadı',
    'Passkeys <0>Recommended</0>': 'Geçiş anahtarları <0>Önerilir</0>',
    'Passkeys need JavaScript. Use a code instead.':
      'Geçiş anahtarları JavaScript gerektirir. Bunun yerine bir kod kullanın.',
    'People may not be able to sign in with single sign-on':
      'Kişiler çoklu oturum açmayla giriş yapamayabilir',
    'People may not be able to sign in with single sign-on.':
      'Kişiler çoklu oturum açmayla giriş yapamayabilir.',
    'People sign in through your identity provider (OpenID Connect or SAML 2.0).':
      'Kişiler kimlik sağlayıcınız üzerinden giriş yapar (OpenID Connect veya SAML 2.0).',
    'People with an address at your verified domains sign in through your identity provider, with OpenID Connect or SAML 2.0: one at a time. A second factor they set up on 2earl is still asked for. Turning single sign-on off also lifts required single sign-on.':
      'Doğrulanmış alan adlarınızda adresi olan kişiler kimlik sağlayıcınız üzerinden OpenID Connect ya da SAML 2.0 ile (aynı anda biri) giriş yapar. 2earl’de kurdukları ikinci doğrulama adımı yine istenir. Çoklu oturum açmayı kapatmak zorunlu çoklu oturum açmayı da kaldırır.',
    'People without one add a passkey or an authenticator app before going on.':
      'Olmayanlar devam etmeden önce bir geçiş anahtarı ya da doğrulama uygulaması ekler.',
    'Phishing-resistant. Authenticator-app codes stop counting once someone has a passkey; recovery codes still work.':
      'Oltalamaya dayanıklı. Biri geçiş anahtarı eklediğinde doğrulama uygulaması kodları sayılmaz; kurtarma kodları çalışmaya devam eder.',
    Privacy: 'Gizlilik',
    'Prompt share ({0})': 'Prompt share ({0})',
    'Protect your account': 'Hesabınızı koruyun',
    'Prove your company controls it, with a DNS record.':
      'Şirketinizin onu kontrol ettiğini bir DNS kaydıyla kanıtlayın.',
    'Published by {0}': 'Yayıncı: {0}',
    'QR code for your authenticator app': 'Doğrulama uygulamanız için QR kod',
    Query: 'Sorgu',
    Reactivate: 'Yeniden etkinleştir',
    Read: 'Okuma',
    'Read and write': 'Okuma ve yazma',
    'Read your prompts and public prompts in Prompt share':
      'Prompt share’deki prompt’larınızı ve herkese açık prompt’ları okuma',
    'Recent activity': 'Son etkinlikler',
    'Recovery code': 'Kurtarma kodu',
    'Recovery code used': 'Kurtarma kodu kullanıldı',
    'Recovery codes': 'Kurtarma kodları',
    'Recovery codes created': 'Kurtarma kodları oluşturuldu',
    'Redirect URI': 'Yönlendirme URI’si',
    'Redirect URIs, one per line (https, or http on localhost)':
      'Yönlendirme URI’leri, her satıra bir tane (https ya da localhost üzerinde http)',
    'Reference: <0/>': 'Referans: <0/>',
    'Register app': 'Uygulama kaydet',
    'Registered apps': 'Kayıtlı uygulamalar',
    Remove: 'Kaldır',
    'Remove from staff': 'Ekipten çıkar',
    'Remove verification': 'Doğrulamayı kaldır',
    'Remove {0}': '{0} kaldır',
    'Removed a second factor': 'Bir doğrulama adımını kaldırdı',
    'Removed a way to sign in': 'Bir giriş yolunu kaldırdı',
    'Removed from an organization': 'Bir kurumdan çıkarıldı',
    'Removed from staff. They were told by email':
      'Ekipten çıkarıldı. Kendisine e-postayla bildirildi',
    'Removed from staff. They were told by email.':
      'Ekipten çıkarıldı. Kendisine e-postayla bildirildi.',
    "Removes a member the organization doesn't manage. <0/> for managed accounts: deactivate them":
      'Kurumun yönetmediği bir üyeyi çıkarır. Yönetilen hesaplarda <0/>: onları devre dışı bırakın',
    Rename: 'Yeniden adlandır',
    'Replace it before then so people can keep signing in.':
      'Kişiler giriş yapmaya devam edebilsin diye o tarihten önce değiştirin.',
    'Reply (ACS) URL': 'Yanıt (ACS) URL’si',
    Request: 'İstek',
    'Require a passkey': 'Geçiş anahtarını zorunlu tut',
    'Require a second factor': 'İkinci doğrulama adımını zorunlu tut',
    'Require single sign-on': 'Çoklu oturum açmayı zorunlu tut',
    'Reset second factor': 'İkinci adımı sıfırla',
    'Resource server credentials created': 'Kaynak sunucusu kimlik bilgileri oluşturuldu',
    'Resource server credentials revoked': 'Kaynak sunucusu kimlik bilgileri iptal edildi',
    'Resource server credentials revoked.': 'Kaynak sunucusu kimlik bilgileri iptal edildi.',
    'Resource servers': 'Kaynak sunucuları',
    Review: 'Gözden geçir',
    'Review connected apps': 'Bağlı uygulamaları gözden geçirin',
    'Review your security': 'Güvenliğinizi gözden geçirin',
    Revoke: 'İptal et',
    Role: 'Rol',
    'Role changed': 'Rol değiştirildi',
    'Role changed.': 'Rol değiştirildi.',
    'Role from directory': 'Rol dizinden',
    'Role given. They were told by email': 'Rol verildi. Kendisine e-postayla bildirildi',
    'Role given. They were told by email.': 'Rol verildi. Kendisine e-postayla bildirildi.',
    'Roles now follow your directory’s groups': 'Roller artık dizininizin gruplarını izliyor',
    'Roles now follow your directory’s groups.': 'Roller artık dizininizin gruplarını izliyor.',
    'SAML certificates refreshed from metadata': 'SAML sertifikaları meta veriden yenilendi',
    'SSO off': 'SSO kapalı',
    'SSO on': 'SSO açık',
    'SSO required': 'SSO zorunlu',
    'Safari on Android': 'Android üzerinde Safari',
    'Safari on ChromeOS': 'ChromeOS üzerinde Safari',
    'Safari on Linux': 'Linux üzerinde Safari',
    'Safari on Windows': 'Windows üzerinde Safari',
    'Safari on iPad': 'iPad üzerinde Safari',
    'Safari on iPhone': 'iPhone üzerinde Safari',
    'Safari on macOS': 'macOS üzerinde Safari',
    'Samsung Internet on Android': 'Android üzerinde Samsung Internet',
    'Samsung Internet on ChromeOS': 'ChromeOS üzerinde Samsung Internet',
    'Samsung Internet on Linux': 'Linux üzerinde Samsung Internet',
    'Samsung Internet on Windows': 'Windows üzerinde Samsung Internet',
    'Samsung Internet on iPad': 'iPad üzerinde Samsung Internet',
    'Samsung Internet on iPhone': 'iPhone üzerinde Samsung Internet',
    'Samsung Internet on macOS': 'macOS üzerinde Samsung Internet',
    Save: 'Kaydet',
    'Save rules': 'Kuralları kaydet',
    'Save single sign-on': 'Çoklu oturum açmayı kaydet',
    'Save to and read your shared sessions in Prompt share, including ones other people can see':
      'Prompt share’deki paylaşılan oturumlarınıza kaydetme ve onları okuma (başkalarının da görebildikleri dahil)',
    'Save your recovery codes': 'Kurtarma kodlarınızı kaydedin',
    'Saved: leave empty to keep it': 'Kaydedildi: korumak için boş bırakın',
    'Scan this code with your authenticator app. It adds 2earl and starts showing six-digit codes.':
      'Bu kodu doğrulama uygulamanızla tarayın. Uygulama 2earl’ü ekler ve altı haneli kodlar göstermeye başlar.',
    'Scheduled deletion of a managed account': 'Yönetilen bir hesabın planlı silinmesi',
    Scopes: 'Kapsamlar',
    'Second factor': 'İkinci doğrulama adımı',
    'Second factor added': 'İkinci doğrulama adımı eklendi',
    'Second factor failed': 'İkinci doğrulama adımı başarısız',
    'Second factor locked after failures': 'Başarısız denemelerden sonra ikinci adım kilitlendi',
    'Second factor locked after too many wrong codes':
      'Çok fazla yanlış koddan sonra ikinci adım kilitlendi',
    'Second factor removed': 'İkinci doğrulama adımı kaldırıldı',
    'Second factor reset': 'İkinci doğrulama adımı sıfırlandı',
    'Second factor reset. The user sets up a new one at their next sign-in':
      'İkinci doğrulama adımı sıfırlandı. Kullanıcı bir sonraki girişinde yenisini kurar',
    'Second factor reset. The user sets up a new one at their next sign-in.':
      'İkinci doğrulama adımı sıfırlandı. Kullanıcı bir sonraki girişinde yenisini kurar.',
    'Second factor used': 'İkinci doğrulama adımı kullanıldı',
    'Second factor, passkeys, session length, ways in, networks.':
      'İkinci doğrulama adımı, geçiş anahtarları, oturum süresi, giriş yolları, ağlar.',
    'Second step': 'İkinci adım',
    'Secret <0/>': 'Sır <0/>',
    Security: 'Güvenlik',
    'Security change in “{0}”': '“{0}” kurumunda güvenlik değişikliği',
    'Security log': 'Güvenlik kaydı',
    'Security log entries, for up to 90 days, no longer linked to your name or email':
      'Artık adınıza veya e-postanıza bağlı olmayan, 90 güne kadar saklanan güvenlik kaydı girişleri',
    'Security rules': 'Güvenlik kuralları',
    'Security rules saved. They apply from each person’s next request':
      'Güvenlik kuralları kaydedildi. Her kişinin bir sonraki isteğinden itibaren geçerli olur',
    'Security rules saved. They apply from each person’s next request.':
      'Güvenlik kuralları kaydedildi. Her kişinin bir sonraki isteğinden itibaren geçerli olur.',
    'See which organizations you belong to, and your role in each':
      'Hangi kurumlara ait olduğunuzu ve her birindeki rolünüzü görme',
    'See which tools are available to you': 'Kullanabileceğiniz araçları görme',
    'See your email address': 'E-posta adresinizi görme',
    'See your name': 'Adınızı görme',
    'Send a new code': 'Yeni kod gönder',
    'Send a test event': 'Deneme olayı gönder',
    'Send again': 'Yeniden gönder',
    'Send events': 'Olayları gönder',
    'Send invitation': 'Davet gönder',
    'Send me a code': 'Bana kod gönder',
    'Send me a code instead': 'Bunun yerine bana kod gönder',
    'Sends access to': 'Erişimi şuraya gönderir',
    'Sessions last': 'Oturum süresi',
    'Set security rules': 'Güvenlik kurallarını belirleyin',
    'Set up': 'Kuruldu',
    'Set up a second factor': 'İkinci doğrulama adımı kurun',
    'Set up an authenticator app': 'Doğrulama uygulaması kurun',
    'Set up organization': 'Kurumu kur',
    'Set up the organization': 'Kurumu kurun',
    'Set up your organization': 'Kurumunuzu kurun',
    'Set up your organization on 2earl': '2earl’de kurumunuzu kurun',
    'Set up {0} for your company': 'Şirketiniz için {0} kurumunu kurun',
    'Set up “{0}”': '“{0}” kurumunu kurun',
    'Set up “{0}” on 2earl': '2earl’de “{0}” kurumunu kurun',
    Settings: 'Ayarlar',
    Setup: 'Kurulum',
    'Setup paused': 'Kurulum duraklatıldı',
    Show: 'Göster',
    'Show all': 'Tümünü göster',
    'Shown to apps you allow and to organizations you join. Leave it empty to show only your address':
      'İzin verdiğiniz uygulamalara ve katıldığınız kurumlara gösterilir. Yalnızca adresinizin görünmesi için boş bırakın',
    'Shown to apps you allow and to organizations you join. Leave it empty to show only your address.':
      'İzin verdiğiniz uygulamalara ve katıldığınız kurumlara gösterilir. Yalnızca adresinizin görünmesi için boş bırakın.',
    'Sign in': 'Giriş yap',
    'Sign in again': 'Yeniden giriş yapın',
    'Sign in again as usual; apps you use need to be connected again. If you didn’t ask for this, write to legal@2earl.com.':
      'Her zamanki gibi yeniden giriş yapın; kullandığınız uygulamaların yeniden bağlanması gerekir. Bunu siz istemediyseniz legal@2earl.com adresine yazın.',
    'Sign in again to continue. It keeps someone who finds your browser signed in from changing your account.':
      'Devam etmek için yeniden giriş yapın. Bu, tarayıcınızı oturumu açık bulan birinin hesabınızı değiştirmesini önler.',
    'Sign in another way': 'Başka bir yolla giriş yapın',
    'Sign in in the same browser': 'Aynı tarayıcıda giriş yapın',
    'Sign in on a device': 'Bir cihazda giriş yapın',
    'Sign in once. Decide which apps may act for you, and take it back at any time.':
      'Bir kez giriş yapın. Hangi uygulamaların sizin adınıza işlem yapabileceğine karar verin ve istediğiniz zaman geri alın.',
    'Sign in or create your account': 'Giriş yapın ya da hesabınızı oluşturun',
    'Sign in to Prompt share': 'Prompt share’e giriş yapın',
    'Sign in to Emanet Kurumsal for your organization':
      'Kuruluşunuz adına Emanet Kurumsal’a giriş yapın',
    'Sign in to Emanet Saha as a field agent': 'Emanet Saha’ya saha görevlisi olarak giriş yapın',
    'Sign in to Emanet Merkez as 2earl staff': 'Emanet Merkez’e 2earl personeli olarak giriş yapın',
    'Sign in to the 2earl KYC console': '2earl KYC konsoluna giriş yapın',
    'Start identity verifications in 2earl KYC for your organization':
      'Kurumunuz adına 2earl KYC’de kimlik doğrulaması başlatma',
    'See the status of your organization’s identity verifications':
      'Kurumunuzun kimlik doğrulamalarının durumunu görme',
    'See the identity details of people your organization verified':
      'Kurumunuzun doğruladığı kişilerin kimlik bilgilerini görme',
    'See the photos taken during your organization’s verifications':
      'Kurumunuzun doğrulamaları sırasında çekilen fotoğrafları görme',
    'Delete verification data your organization holds in 2earl KYC':
      'Kurumunuzun 2earl KYC’deki doğrulama verilerini silme',
    'Change your organization’s KYC workflows and webhooks':
      'Kurumunuzun KYC iş akışlarını ve webhook’larını değiştirme',
    'See your organization’s KYC usage, plan and statements':
      'Kurumunuzun KYC kullanımını, planını ve hesap dökümlerini görme',
    'Sign in with': 'Giriş yöntemi',
    'Sign in with SSO': 'SSO ile giriş yapın',
    'Sign in with a passkey': 'Geçiş anahtarıyla giriş yapın',
    'Sign in with an email address': 'Bir e-posta adresiyle giriş yapın',
    'Sign in with email': 'E-postayla giriş yapın',
    'Sign in with single sign-on': 'Çoklu oturum açmayla giriş yapın',
    'Sign in with your organization': 'Kurumunuzla giriş yapın',
    'Sign in with your organization (SSO)': 'Kurumunuzla giriş yapın (SSO)',
    'Sign out': 'Çıkış yap',
    'Sign out all other devices': 'Diğer tüm cihazlarda oturumu kapat',
    'Sign out everywhere': 'Her yerde oturumu kapat',
    'Sign out of 2earl?': '2earl’den çıkış yapılsın mı?',
    'Sign you in with your 2earl account, with an ID only this app gets':
      'Yalnızca bu uygulamanın aldığı bir kimlikle 2earl hesabınızla girişinizi yapma',
    'Sign {0} out everywhere': '{0} hesabının tüm oturumlarını kapat',
    'Sign-in': 'Giriş',
    'Sign-in &amp; security': 'Giriş ve güvenlik',
    'Sign-in URL (HTTP-Redirect)': 'Giriş URL’si (HTTP-Redirect)',
    'Sign-in didn’t complete': 'Giriş tamamlanmadı',
    'Sign-in failed': 'Giriş başarısız',
    'Sign-in is paused for this network for a minute. Wait, then try again.':
      'Bu ağ için giriş bir dakikalığına durduruldu. Bekleyin, sonra yeniden deneyin.',
    'Sign-in link for your app dashboard': 'Uygulama panonuz için giriş bağlantısı',
    'Sign-in method added': 'Giriş yöntemi eklendi',
    'Sign-in method removed': 'Giriş yöntemi kaldırıldı',
    'Sign-in refused (not invited)': 'Giriş reddedildi (davetli değil)',
    'Sign-in started': 'Giriş başladı',
    'Sign-in stopped': 'Giriş durduruldu',
    'Sign-up': 'Kayıt',
    'Sign-up is by invitation for now. If you were invited, use the Google account or the address the invitation was for.':
      'Kayıt şimdilik davetle. Davet edildiyseniz davetin yapıldığı Google hesabını ya da adresi kullanın.',
    'Sign-up is by invitation for now. Use the Google account or the address you were invited with.':
      'Kayıt şimdilik davetle. Davet edildiğiniz Google hesabını ya da adresi kullanın.',
    'Sign-up is closed. New accounts need an invitation':
      'Kayıt kapalı. Yeni hesaplar için davet gerekir',
    'Sign-up is closed. New accounts need an invitation.':
      'Kayıt kapalı. Yeni hesaplar için davet gerekir.',
    'Sign-up is open. Anyone can create an account': 'Kayıt açık. Herkes hesap oluşturabilir',
    'Sign-up is open. Anyone can create an account.': 'Kayıt açık. Herkes hesap oluşturabilir.',
    'Sign-up switched': 'Kayıt modu değiştirildi',
    Signature: 'İmza',
    'Signed in': 'Giriş yaptı',
    'Signed in a device with a code': 'Bir cihazda kodla giriş yaptı',
    'Signed in on a device': 'Bir cihazda giriş yapıldı',
    'Signed in with Google': 'Google ile giriş yaptı',
    'Signed in with a passkey': 'Geçiş anahtarıyla giriş yaptı',
    'Signed in with an email code': 'E-posta koduyla giriş yaptı',
    'Signed in with your organization’s sign-in (SSO)':
      'Kurumunuzun giriş hizmetiyle (SSO) giriş yaptı',
    'Signed in with {0}': '{0} ile giriş yaptı',
    'Signed in {0} with {1}': '{0} tarihinde {1} ile giriş yapıldı',
    'Signed out': 'Çıkış yapıldı',
    'Signed out a device': 'Bir cihazın oturumunu kapattı',
    'Signed out everywhere and disconnected from their apps. They were told by email':
      'Her yerde oturumu kapatıldı ve uygulamalarının bağlantısı kesildi. Kendisine e-postayla bildirildi',
    'Signed out everywhere and disconnected from their apps. They were told by email.':
      'Her yerde oturumu kapatıldı ve uygulamalarının bağlantısı kesildi. Kendisine e-postayla bildirildi.',
    'Signed out everywhere. Its sessions ended and its apps lost access; it can sign in again':
      'Her yerde oturum kapatıldı. Oturumları sona erdi ve uygulamaları erişimini kaybetti; yeniden giriş yapabilir',
    'Signed out everywhere. Its sessions ended and its apps lost access; it can sign in again.':
      'Her yerde oturum kapatıldı. Oturumları sona erdi ve uygulamaları erişimini kaybetti; yeniden giriş yapabilir.',
    'Signed out other devices': 'Diğer cihazlarda oturum kapatıldı',
    'Signed-in devices': 'Oturumu açık cihazlar',
    'Signing certificate (PEM or base64)': 'İmzalama sertifikası (PEM veya base64)',
    'Signing certificate (PEM or base64) <0>Expires {0}</0>':
      'İmzalama sertifikası (PEM veya base64) <0>Bitiş {0}</0>',
    'Signing out a device doesn’t disconnect apps: they keep their access until you disconnect them under <0>Connected apps</0>.':
      'Bir cihazın oturumunu kapatmak uygulamaların bağlantısını kesmez: <0>Bağlı uygulamalar</0> altında bağlantılarını kesene kadar erişimlerini korurlar.',
    'Signs a managed account out everywhere: sessions and app access end, the account stays active. <0/> otherwise':
      'Yönetilen bir hesabın tüm oturumlarını kapatır: oturumlar ve uygulama erişimi sona erer, hesap etkin kalır. Aksi halde <0/>',
    'Single sign-on': 'Çoklu oturum açma',
    'Single sign-on expires soon': 'Çoklu oturum açmanın süresi yakında doluyor',
    'Single sign-on is always allowed while it’s on.':
      'Çoklu oturum açma, açıkken her zaman izinlidir.',
    'Single sign-on isn’t on': 'Çoklu oturum açma açık değil',
    'Single sign-on needs attention': 'Çoklu oturum açma ilgi bekliyor',
    'Single sign-on saved': 'Çoklu oturum açma kaydedildi',
    'Single sign-on saved.': 'Çoklu oturum açma kaydedildi.',
    'Single sign-on settings saved': 'Çoklu oturum açma ayarları kaydedildi',
    'Six-digit codes from an app such as Google Authenticator, Microsoft Authenticator, 1Password or Aegis.':
      'Google Authenticator, Microsoft Authenticator, 1Password veya Aegis gibi bir uygulamadan altı haneli kodlar.',
    Someone: 'Biri',
    'Something went wrong': 'Bir şeyler ters gitti',
    'Something went wrong on our side': 'Bizim tarafımızda bir şeyler ters gitti',
    'Something went wrong on our side, and no code was sent. Try again in a minute, or continue with Google.':
      'Bizim tarafımızda bir şeyler ters gitti ve kod gönderilmedi. Bir dakika sonra yeniden deneyin ya da Google ile devam edin.',
    'Something went wrong on our side. Your apps may already be disconnected, but your account still exists. Try again in a minute':
      'Bizim tarafımızda bir şeyler ters gitti. Uygulamalarınızın bağlantısı kesilmiş olabilir, ama hesabınız hâlâ duruyor. Bir dakika sonra yeniden deneyin',
    'Something went wrong on our side. Your apps may already be disconnected, but your account still exists. Try again in a minute.':
      'Bizim tarafımızda bir şeyler ters gitti. Uygulamalarınızın bağlantısı kesilmiş olabilir, ama hesabınız hâlâ duruyor. Bir dakika sonra yeniden deneyin.',
    Staff: 'Ekip',
    'Staff accounts are managed by the owner.': 'Ekip hesaplarını sahip yönetir.',
    'Staff role given': 'Ekip rolü verildi',
    'Staff role removed': 'Ekip rolü kaldırıldı',
    Start: 'Başlangıç',
    'Start again': 'Yeniden başlayın',
    'Start again here': 'Buradan yeniden başlayın',
    'Start again on your device to get a new code':
      'Yeni bir kod almak için cihazınızda yeniden başlayın',
    'Start again on your device to get a new code.':
      'Yeni bir kod almak için cihazınızda yeniden başlayın.',
    Status: 'Durum',
    'Stay signed in': 'Oturum açık kalsın',
    'Stop managing': 'Yönetmeyi bırak',
    'Stream removed. Nothing more is sent': 'Akış kaldırıldı. Artık hiçbir şey gönderilmez',
    'Stream removed. Nothing more is sent.': 'Akış kaldırıldı. Artık hiçbir şey gönderilmez.',
    'Stream saved. New events go out within a minute.':
      'Akış kaydedildi. Yeni olaylar bir dakika içinde gönderilir.',
    'Stream to your security monitoring': 'Güvenlik izleme sisteminize akışla aktarın',
    Support: 'Destek',
    Suspend: 'Askıya al',
    Suspended: 'Askıya alındı',
    'Teams you belong to. Everyone keeps their own account; an organization shows who belongs to it and with which role.':
      'Ait olduğunuz ekipler. Herkes kendi hesabını korur; bir kurum kimlerin ona hangi rolle ait olduğunu gösterir.',
    Terms: 'Koşullar',
    'Test event delivered (HTTP {0})': 'Deneme olayı iletildi (HTTP {0})',
    'Test event delivered (HTTP {0}).': 'Deneme olayı iletildi (HTTP {0}).',
    'That Google account belongs to another 2earl account':
      'Bu Google hesabı başka bir 2earl hesabına ait',
    'That account is managed by an organization. Staff need an account of their own':
      'Bu hesap bir kurum tarafından yönetiliyor. Ekip üyelerinin kendilerine ait bir hesabı olmalı',
    'That account is managed by an organization. Staff need an account of their own.':
      'Bu hesap bir kurum tarafından yönetiliyor. Ekip üyelerinin kendilerine ait bir hesabı olmalı.',
    'That account is suspended. Reactivate it first':
      'Bu hesap askıya alındı. Önce yeniden etkinleştirin',
    'That account is suspended. Reactivate it first.':
      'Bu hesap askıya alındı. Önce yeniden etkinleştirin.',
    'That address already belongs to a member.': 'Bu adres zaten bir üyeye ait.',
    'That address already has an invitation waiting. Send it again instead.':
      'Bu adresin bekleyen bir daveti var. Bunun yerine onu yeniden gönderin.',
    'That address already has an open invitation. Withdraw it to send a new one.':
      'Bu adresin açık bir daveti var. Yenisini göndermek için onu geri alın.',
    'That address belongs to another 2earl account': 'Bu adres başka bir 2earl hesabına ait',
    'That address is already invited': 'Bu adres zaten davet edildi',
    'That address is already invited.': 'Bu adres zaten davet edildi.',
    'That address is your only way to sign in. Add another one first: a different email address, or a Google account.':
      'Bu adres tek giriş yolunuz. Önce bir tane daha ekleyin: farklı bir e-posta adresi ya da bir Google hesabı.',
    'That code didn’t match. Check the app shows 2earl and enter its current code.':
      'Kod eşleşmedi. Uygulamanın 2earl’ü gösterdiğinden emin olun ve güncel kodunu girin.',
    'That code didn’t work. Enter the current code from your app.':
      'Kod çalışmadı. Uygulamanızdaki güncel kodu girin.',
    'That code isn’t right. {0} tries left.': 'Kod doğru değil. {0} deneme hakkınız kaldı.',
    'That code isn’t right. {0} try left.': 'Kod doğru değil. {0} deneme hakkınız kaldı.',
    'That code isn’t valid or has expired. Check it on your device, or start again there.':
      'Kod geçerli değil ya da süresi dolmuş. Cihazınızda denetleyin ya da orada yeniden başlayın.',
    'That code no longer works': 'Bu kod artık çalışmıyor',
    'That device is signed out': 'O cihazın oturumu kapatıldı',
    'That device is signed out.': 'O cihazın oturumu kapatıldı.',
    'That domain isn’t on this organization': 'Bu alan adı bu kurumda değil',
    'That domain isn’t on this organization.': 'Bu alan adı bu kurumda değil.',
    'That group no longer exists': 'Bu grup artık yok',
    'That group no longer exists.': 'Bu grup artık yok.',
    'That invitation no longer exists': 'Bu davet artık yok',
    'That invitation no longer exists.': 'Bu davet artık yok.',
    'That invitation was sent in the last 10 minutes, or isn’t waiting any more.':
      'Bu davet son 10 dakika içinde gönderildi ya da artık beklemiyor.',
    'That organization no longer exists': 'Bu kurum artık yok',
    'That organization no longer exists.': 'Bu kurum artık yok.',
    'That passkey didn’t work. Try again': 'Bu geçiş anahtarı çalışmadı. Yeniden deneyin',
    'That passkey didn’t work. Try again.': 'Bu geçiş anahtarı çalışmadı. Yeniden deneyin.',
    'That person is no longer a member': 'Bu kişi artık üye değil',
    'That person is no longer a member.': 'Bu kişi artık üye değil.',
    'That person is no longer on staff.': 'Bu kişi artık ekipte değil.',
    'That recovery code didn’t work, or was already used.':
      'Bu kurtarma kodu çalışmadı ya da zaten kullanıldı.',
    'That user no longer exists': 'Bu kullanıcı artık yok',
    'That user no longer exists.': 'Bu kullanıcı artık yok.',
    'That’s you: the owner already has every permission':
      'Bu sizsiniz: sahibin zaten her yetkisi var',
    'That’s you: the owner already has every permission.':
      'Bu sizsiniz: sahibin zaten her yetkisi var.',
    'The 2earl account and everything in it are deleted now, in every 2earl service, and every connected app loses access. It can’t be restored. Deactivating keeps the account instead.':
      '2earl hesabı ve içindeki her şey her 2earl hizmetinde şimdi silinir ve her bağlı uygulama erişimini kaybeder. Geri getirilemez. Devre dışı bırakmak ise hesabı korur.',
    'The API key “{0}” made {1} ({2}) an admin in “{3}”.':
      '“{0}” API anahtarı, “{3}” kurumunda {1} ({2}) kişisini yönetici yaptı.',
    'The API key “{0}” made {1} ({2}) an admin.':
      '“{0}” API anahtarı {1} ({2}) kişisini yönetici yaptı.',
    'The API key “{0}” {1} in “{2}”': '“{0}” API anahtarı, “{2}” kurumunda: {1}',
    'The API key “{0}” {1} in “{2}”.': '“{0}” API anahtarı, “{2}” kurumunda: {1}.',
    'The OpenID Connect client secret for “{0}” expired on {1}. People may not be able to sign in with single sign-on':
      '“{0}” kurumunun OpenID Connect istemci sırrının süresi {1} tarihinde doldu. Kişiler çoklu oturum açmayla giriş yapamayabilir',
    'The OpenID Connect client secret for “{0}” expired on {1}. People may not be able to sign in with single sign-on.':
      '“{0}” kurumunun OpenID Connect istemci sırrının süresi {1} tarihinde doldu. Kişiler çoklu oturum açmayla giriş yapamayabilir.',
    'The OpenID Connect client secret for “{0}” expires on {1}.':
      '“{0}” kurumunun OpenID Connect istemci sırrının süresi {1} tarihinde doluyor.',
    'The TXT record isn’t there yet. DNS changes can take a while to appear; check again later.':
      'TXT kaydı henüz orada değil. DNS değişikliklerinin görünmesi biraz sürebilir; daha sonra yeniden denetleyin.',
    'The account couldn’t be deleted. Nothing changed; try again':
      'Hesap silinemedi. Hiçbir şey değişmedi; yeniden deneyin',
    'The account couldn’t be deleted. Nothing changed; try again.':
      'Hesap silinemedi. Hiçbir şey değişmedi; yeniden deneyin.',
    'The admin area opens only after you confirm it’s you with a passkey or authenticator app.':
      'Yönetim alanı ancak kimliğinizi bir geçiş anahtarı veya doğrulama uygulamasıyla doğruladıktan sonra açılır.',
    'The app sent an authorization request 2earl can’t accept, so nothing was shared. Return to the app and try connecting again; if it keeps happening, the app needs fixing.':
      'Uygulama 2earl’ün kabul edemeyeceği bir yetkilendirme isteği gönderdi, bu yüzden hiçbir şey paylaşılmadı. Uygulamaya dönün ve yeniden bağlanmayı deneyin; devam ederse uygulamanın düzeltilmesi gerekir.',
    'The app’s client ID, or its https client metadata URL':
      'Uygulamanın istemci kimliği ya da https istemci meta veri URL’si',
    'The app’s published details could not be loaded or are invalid, so nothing was shared. Try again later':
      'Uygulamanın yayımladığı bilgiler yüklenemedi ya da geçersiz, bu yüzden hiçbir şey paylaşılmadı. Daha sonra yeniden deneyin',
    'The app’s published details could not be loaded or are invalid, so nothing was shared. Try again later.':
      'Uygulamanın yayımladığı bilgiler yüklenemedi ya da geçersiz, bu yüzden hiçbir şey paylaşılmadı. Daha sonra yeniden deneyin.',
    'The code and the link work once, for 10 minutes.':
      'Kod ve bağlantı bir kez ve 10 dakika boyunca çalışır.',
    'The confirmation expired, was cancelled, or you signed out in between. Try again from your account page':
      'Onayın süresi doldu, iptal edildi ya da arada çıkış yaptınız. Hesap sayfanızdan yeniden deneyin',
    'The confirmation expired, was cancelled, or you signed out in between. Try again from your account page.':
      'Onayın süresi doldu, iptal edildi ya da arada çıkış yaptınız. Hesap sayfanızdan yeniden deneyin.',
    'The consent page shows these as verified instead of “This app named itself”. Verify only apps whose publisher you have checked.':
      'Onay sayfası bunları “Bu uygulama kendine bu adı verdi” yerine doğrulanmış olarak gösterir. Yalnızca yayıncısını kontrol ettiğiniz uygulamaları doğrulayın.',
    'The earlier recovery codes no longer work': 'Önceki kurtarma kodları artık çalışmıyor',
    'The earlier recovery codes no longer work.': 'Önceki kurtarma kodları artık çalışmıyor.',
    'The identity provider’s signing certificate for “{0}” expired on {1}. People may not be able to sign in with single sign-on':
      '“{0}” kurumunun kimlik sağlayıcı imzalama sertifikasının süresi {1} tarihinde doldu. Kişiler çoklu oturum açmayla giriş yapamayabilir',
    'The identity provider’s signing certificate for “{0}” expired on {1}. People may not be able to sign in with single sign-on.':
      '“{0}” kurumunun kimlik sağlayıcı imzalama sertifikasının süresi {1} tarihinde doldu. Kişiler çoklu oturum açmayla giriş yapamayabilir.',
    'The identity provider’s signing certificate for “{0}” expires on {1}.':
      '“{0}” kurumunun kimlik sağlayıcı imzalama sertifikasının süresi {1} tarihinde doluyor.',
    'The invitation works for 7 days, and only for this address. If you don’t know who sent it, you can ignore this email.':
      'Davet 7 gün boyunca ve yalnızca bu adres için geçerlidir. Kimin gönderdiğini bilmiyorsanız bu e-postayı yok sayabilirsiniz.',
    'The invitation works until {0}, and only for this address. If you weren’t expecting it, you can ignore this email.':
      'Davet {0} tarihine kadar ve yalnızca bu adres için geçerlidir. Beklemiyorduysanız bu e-postayı yok sayabilirsiniz.',
    'The last 30 days. If you see something you didn’t do, sign out the device under <0>Devices</0>, then add a second factor.':
      'Son 30 gün. Yapmadığınız bir şey görürseniz <0>Cihazlar</0> altında o cihazın oturumunu kapatın, ardından ikinci bir doğrulama adımı ekleyin.',
    'The latest 200 events of the last 90 days, newest first. The sign-ins and security changes of accounts your organization manages are included.':
      'Son 90 günün en son 200 olayı, en yenisi önce. Kurumunuzun yönettiği hesapların girişleri ve güvenlik değişiklikleri dahildir.',
    'The latest 200 events, times in UTC. Entries are kept for 90 days.':
      'En son 200 olay, zamanlar UTC. Girişler 90 gün saklanır.',
    'The link works for 7 days, for that address only. Owners are made from members once they’ve joined.':
      'Bağlantı 7 gün boyunca, yalnızca o adres için çalışır. Sahipler, katıldıktan sonra üyeler arasından belirlenir.',
    'The metadata URL answered {0}.': 'Meta veri adresi {0} yanıtını verdi.',
    'The metadata URL must be an https URL.': 'Meta veri adresi bir https URL’si olmalıdır.',
    'The metadata couldn’t be read: {0}': 'Meta veri okunamadı: {0}',
    'The name you typed doesn’t match. Nothing was deleted.':
      'Yazdığınız ad eşleşmiyor. Hiçbir şey silinmedi.',
    'The next signing certificate isn’t one: paste it as PEM or base64, or leave it empty.':
      'Sonraki imzalama sertifikası geçerli değil: PEM veya base64 olarak yapıştırın ya da boş bırakın.',
    'The organization API': 'Kurum API’si',
    'The organization manages this account: deactivate it instead of removing it.':
      'Bu hesabı kurum yönetiyor: çıkarmak yerine devre dışı bırakın.',
    'The organization sees in its activity that 2earl staff opened this page (not who).':
      'Kurum, etkinlik kaydında bu sayfayı 2earl ekibinin açtığını görür (kimin açtığını değil).',
    'The organization “{0}” proved it controls {1} and now manages the 2earl accounts there.':
      '“{0}” kurumu {1} alan adını kontrol ettiğini kanıtladı ve artık oradaki 2earl hesaplarını yönetiyor.',
    'The organization “{0}”, which has no other members': 'Başka üyesi olmayan “{0}” kurumu',
    "The organization's audit log, <0>oldest first</0>, from the last 90 days: everything that names the organization, and everything the accounts it manages did.":
      'Kurumun son 90 günlük denetim kaydı, <0>en eskisi önce</0>: kurumu belirten her şey ve yönettiği hesapların yaptığı her şey.',
    'The organization, its {0} memberships and its open invitations are deleted now, and 2earl services are told to delete what they keep for it. It can’t be restored. Everyone keeps their own 2earl account.':
      'Kurum, {0} üyeliği ve açık davetleri şimdi silinir ve 2earl hizmetlerine onun için tuttuklarını silmeleri bildirilir. Geri getirilemez. Herkes kendi 2earl hesabını korur.',
    'The passkey couldn’t be verified. Try again': 'Geçiş anahtarı doğrulanamadı. Yeniden deneyin',
    'The passkey couldn’t be verified. Try again.':
      'Geçiş anahtarı doğrulanamadı. Yeniden deneyin.',
    'The sign-in link expired, was already used, or was cancelled. Start again to get a new one.':
      'Giriş bağlantısının süresi doldu, zaten kullanıldı ya da iptal edildi. Yenisini almak için yeniden başlayın.',
    'The test wasn’t accepted: {0}': 'Deneme kabul edilmedi: {0}',
    'The work email address': 'İş e-posta adresi',
    'There’s no passkey on this account': 'Bu hesapta geçiş anahtarı yok',
    'There’s no passkey on this account.': 'Bu hesapta geçiş anahtarı yok.',
    'There’s nothing at this address': 'Bu adreste bir şey yok',
    'These aren’t network ranges (or are wider than /8 or /16): {0}.':
      'Bunlar ağ aralığı değil (ya da /8 veya /16’dan geniş): {0}.',
    'They already have that role': 'Zaten bu role sahip',
    'They already have that role.': 'Zaten bu role sahip.',
    'This account can’t sign in': 'Bu hesap giriş yapamıyor',
    'This account can’t sign in yet': 'Bu hesap henüz giriş yapamıyor',
    'This account is suspended. If you think that’s a mistake, write to us through the contact form on 2earl.com':
      'Bu hesap askıya alındı. Bunun bir hata olduğunu düşünüyorsanız 2earl.com’daki iletişim formuyla bize yazın',
    'This account is suspended. If you think that’s a mistake, write to us through the contact form on 2earl.com.':
      'Bu hesap askıya alındı. Bunun bir hata olduğunu düşünüyorsanız 2earl.com’daki iletişim formuyla bize yazın.',
    'This address already has an account': 'Bu adresin zaten bir hesabı var',
    'This app couldn’t be checked': 'Bu uygulama denetlenemedi',
    'This app named itself. 2earl has not verified who runs it.':
      'Bu uygulama adını kendisi verdi. 2earl onu kimin işlettiğini doğrulamadı.',
    'This approval page has expired': 'Bu onay sayfasının süresi doldu',
    'This app’s request isn’t valid': 'Bu uygulamanın isteği geçerli değil',
    'This device': 'Bu cihaz',
    'This invitation no longer works': 'Bu davet artık geçerli değil',
    'This invitation works until {0}, once.': 'Bu davet {0} tarihine kadar, bir kez geçerli.',
    'This invitation works until {0}.': 'Bu davet {0} tarihine kadar geçerli.',
    'This is the last email you get from us about this account.':
      'Bu hesapla ilgili bizden aldığınız son e-posta budur.',
    'This is the only device signed in.': 'Oturumu açık tek cihaz bu.',
    'This organization doesn’t manage that account.': 'Bu kurum o hesabı yönetmiyor.',
    'This organization doesn’t sign people in with single sign-on on 2earl. Sign in another way, or ask its admins.':
      'Bu kurum 2earl’de kişilerin çoklu oturum açmayla giriş yapmasını sağlamıyor. Başka bir yolla giriş yapın ya da yöneticilerine sorun.',
    'This organization has reached its limit: 1,000 members and invitations, or 100 open invitations':
      'Bu kurum sınırına ulaştı: 1.000 üye ve davet ya da 100 açık davet',
    'This organization has reached its limit: 1,000 members and invitations, or 100 open invitations.':
      'Bu kurum sınırına ulaştı: 1.000 üye ve davet ya da 100 açık davet.',
    'This organization has two tokens. Revoke one first':
      'Bu kurumun iki token’ı var. Önce birini iptal edin',
    'This organization has two tokens. Revoke one first.':
      'Bu kurumun iki token’ı var. Önce birini iptal edin.',
    'This organization is suspended by 2earl. Nothing in it can be changed, and 2earl services don’t see it. Write to us through the contact form on 2earl.com if you think that’s a mistake.':
      'Bu kurum 2earl tarafından askıya alındı. İçindeki hiçbir şey değiştirilemez ve 2earl hizmetleri onu görmez. Bunun bir hata olduğunu düşünüyorsanız 2earl.com’daki iletişim formuyla bize yazın.',
    'This organization is suspended.': 'Bu kurum askıya alındı.',
    'This organization manages your account, so you can’t leave it. Ask its admins.':
      'Bu kurum hesabınızı yönettiği için ondan ayrılamazsınız. Yöneticilerine sorun.',
    'This passkey is already registered': 'Bu geçiş anahtarı zaten kayıtlı',
    'This passkey is already registered.': 'Bu geçiş anahtarı zaten kayıtlı.',
    'This passkey isn’t on a 2earl account. Sign in another way, then add it under Security':
      'Bu geçiş anahtarı bir 2earl hesabında değil. Başka bir yolla giriş yapın, ardından Güvenlik altında ekleyin',
    'This passkey isn’t on a 2earl account. Sign in another way, then add it under Security.':
      'Bu geçiş anahtarı bir 2earl hesabında değil. Başka bir yolla giriş yapın, ardından Güvenlik altında ekleyin.',
    'This request expired. Try again': 'Bu isteğin süresi doldu. Yeniden deneyin',
    'This request expired. Try again.': 'Bu isteğin süresi doldu. Yeniden deneyin.',
    'This request has expired': 'Bu isteğin süresi doldu',
    'Tick the box to confirm the deletion.': 'Silmeyi onaylamak için kutuyu işaretleyin.',
    'Tick the box to confirm.': 'Onaylamak için kutuyu işaretleyin.',
    Time: 'Zaman',
    'Time (UTC)': 'Zaman (UTC)',
    'To change your own membership, use Leave below, or ask another owner.':
      'Kendi üyeliğinizi değiştirmek için aşağıdaki Ayrıl’ı kullanın ya da başka bir sahibe sorun.',
    'To follow the log, store <0/> and ask again with it; with no new events the same cursor comes back. Events of the last few seconds appear on the next call.':
      'Kaydı izlemek için <0/> değerini saklayın ve onunla yeniden sorun; yeni olay yoksa aynı imleç döner. Son birkaç saniyenin olayları bir sonraki çağrıda görünür.',
    'To manage accounts, accept the data processing terms: you decide over them.':
      'Hesapları yönetmek için veri işleme koşullarını kabul edin: onlar hakkında siz karar verirsiniz.',
    'To set one up for your company, write to us through the contact form on 2earl.com. To join an organization that exists, ask one of its owners or admins to invite you.':
      'Şirketiniz için bir kurum kurmak isterseniz 2earl.com’daki iletişim formuyla bize yazın. Var olan bir kuruma katılmak için sahiplerinden ya da yöneticilerinden birinden sizi davet etmesini isteyin.',
    'Token revoked. Your directory can no longer use it':
      'Token iptal edildi. Dizininiz artık onu kullanamaz',
    'Token revoked. Your directory can no longer use it.':
      'Token iptal edildi. Dizininiz artık onu kullanamaz.',
    'Too many attempts from this network. Wait a minute':
      'Bu ağdan çok fazla deneme. Bir dakika bekleyin',
    'Too many attempts from this network. Wait a minute, then try again':
      'Bu ağdan çok fazla deneme. Bir dakika bekleyin, sonra yeniden deneyin',
    'Too many attempts from this network. Wait a minute, then try again.':
      'Bu ağdan çok fazla deneme. Bir dakika bekleyin, sonra yeniden deneyin.',
    'Too many attempts from this network. Wait a minute.':
      'Bu ağdan çok fazla deneme. Bir dakika bekleyin.',
    'Too many codes for now': 'Şimdilik çok fazla kod',
    'Too many failed attempts. Try again later':
      'Çok fazla başarısız deneme. Daha sonra yeniden deneyin',
    'Too many failed attempts. Try again later.':
      'Çok fazla başarısız deneme. Daha sonra yeniden deneyin.',
    'Too many invitations are waiting (200). Withdraw some first':
      'Çok fazla bekleyen davet var (200). Önce bazılarını geri alın',
    'Too many invitations are waiting (200). Withdraw some first.':
      'Çok fazla bekleyen davet var (200). Önce bazılarını geri alın.',
    'Too many sign-in attempts': 'Çok fazla giriş denemesi',
    'Too many tries. Wait a minute': 'Çok fazla deneme. Bir dakika bekleyin',
    'Too many tries. Wait a minute.': 'Çok fazla deneme. Bir dakika bekleyin.',
    'Too many wrong codes. Try again after {0} UTC.':
      'Çok fazla yanlış kod. {0} UTC’den sonra yeniden deneyin.',
    'Try again': 'Yeniden deneyin',
    'Try another account': 'Başka bir hesap deneyin',
    'Turn on': 'Aç',
    'Turn on single sign-on below first.': 'Önce aşağıdan çoklu oturum açmayı açın.',
    'Turn on single sign-on first': 'Önce çoklu oturum açmayı açın',
    'Turn on single sign-on first.': 'Önce çoklu oturum açmayı açın.',
    'Turned on': 'Açıldı',
    'Type the organization’s name to confirm': 'Onaylamak için kurumun adını yazın',
    'Unknown action': 'Bilinmeyen işlem',
    'Unknown action.': 'Bilinmeyen işlem.',
    'Until you choose, your account works only for this. You can also <0>download your data</0> or <1>delete your account</1>.':
      'Siz seçene kadar hesabınız yalnızca bunun için çalışır. Ayrıca <0>verilerinizi indirebilir</0> ya da <1>hesabınızı silebilirsiniz</1>.',
    'Up to 5 keys. Every change made with a key is in the activity, with the key’s ID.':
      'En fazla 5 anahtar. Bir anahtarla yapılan her değişiklik, anahtarın kimliğiyle birlikte etkinlik kaydındadır.',
    'Up to two tokens, so you can rotate: create the new one, put it in your directory, then revoke the old one.':
      'Değiştirebilmeniz için en fazla iki token: yenisini oluşturun, dizininize koyun, ardından eskisini iptal edin.',
    'Use 1 to 60 characters, without links or web addresses.':
      'Bağlantı veya web adresi olmadan 1 ile 60 arasında karakter kullanın.',
    'Use a different address, or Google': 'Farklı bir adres ya da Google kullanın',
    'Use a passkey': 'Geçiş anahtarı kullan',
    'Use a recovery code': 'Kurtarma kodu kullan',
    'Use code': 'Kodu kullan',
    'Use your own tenant’s issuer: https://login.microsoftonline.com/&lt;tenant ID&gt;/v2.0.':
      'Kendi kiracınızın yayıncısını kullanın: https://login.microsoftonline.com/&lt;kiracı kimliği&gt;/v2.0.',
    'Used a recovery code': 'Bir kurtarma kodu kullandı',
    'User deleted': 'Kullanıcı silindi',
    'User reactivated': 'Kullanıcı yeniden etkinleştirildi',
    'User reactivated.': 'Kullanıcı yeniden etkinleştirildi.',
    'User signed out everywhere by staff':
      'Kullanıcının oturumları ekip tarafından her yerde kapatıldı',
    'User suspended': 'Kullanıcı askıya alındı',
    'User suspended, signed out and disconnected from their apps':
      'Kullanıcı askıya alındı, oturumları kapatıldı ve uygulamalarının bağlantısı kesildi',
    'User suspended, signed out and disconnected from their apps.':
      'Kullanıcı askıya alındı, oturumları kapatıldı ve uygulamalarının bağlantısı kesildi.',
    Users: 'Kullanıcılar',
    'Verification removed': 'Doğrulama kaldırıldı',
    'Verification removed.': 'Doğrulama kaldırıldı.',
    Verified: 'Doğrulandı',
    'Verified apps': 'Doğrulanmış uygulamalar',
    'Verified {0}': '{0} tarihinde doğrulandı',
    Verify: 'Doğrula',
    'Verify a domain': 'Bir alan adı doğrulayın',
    'Verify a domain first.': 'Önce bir alan adı doğrulayın.',
    'Verify your company’s domains, manage the 2earl accounts at them, connect your directory (Okta, Microsoft Entra ID or any SCIM 2.0 client) and your single sign-on.':
      'Şirketinizin alan adlarını doğrulayın, oradaki 2earl hesaplarını yönetin, dizininizi (Okta, Microsoft Entra ID ya da herhangi bir SCIM 2.0 istemcisi) ve çoklu oturum açma hizmetinizi bağlayın.',
    'Verify your domain, manage your people’s accounts, connect your single sign-on and directory, and set security rules. {0} of 5 done.':
      'Alan adınızı doğrulayın, kişilerinizin hesaplarını yönetin, çoklu oturum açma hizmetinizi ve dizininizi bağlayın ve güvenlik kurallarını belirleyin. 5 adımdan {0} tanesi tamam.',
    Waiting: 'Bekliyor',
    'Waiting for the first events': 'İlk olaylar bekleniyor',
    'Waiting for you': 'Sizi bekliyor',
    'Waiting to join <0>{0}</0>': 'Katılmayı bekleyenler <0>{0}</0>',
    'Want a copy first? <0>Download your data</0>.':
      'Önce bir kopya mı istiyorsunuz? <0>Verilerinizi indirin</0>.',
    'Ways to sign in': 'Giriş yolları',
    'We accept 2earl’s <0>data processing terms</0> for these accounts':
      'Bu hesaplar için 2earl’ün <0>veri işleme koşullarını</0> kabul ediyoruz',
    'We couldn’t look the record up just now. Try again in a minute':
      'Kaydı şu an sorgulayamadık. Bir dakika sonra yeniden deneyin',
    'We couldn’t look the record up just now. Try again in a minute.':
      'Kaydı şu an sorgulayamadık. Bir dakika sonra yeniden deneyin.',
    'We couldn’t send the email': 'E-postayı gönderemedik',
    'We remove <0>{0}</0> from your account. Everything else stays, and you sign in another way.':
      '<0>{0}</0> adresini hesabınızdan kaldırırız. Diğer her şey kalır ve başka bir yolla giriş yaparsınız.',
    'We send a code to the address to check it’s yours. After that, you can sign in with a code sent there':
      'Adresin size ait olduğunu denetlemek için oraya bir kod göndeririz. Ardından oraya gönderilen bir kodla giriş yapabilirsiniz',
    'We send a code to the address to check it’s yours. After that, you can sign in with a code sent there.':
      'Adresin size ait olduğunu denetlemek için oraya bir kod göndeririz. Ardından oraya gönderilen bir kodla giriş yapabilirsiniz.',
    'We sent a 6-digit code to <0>{0}</0>. It works for 10 minutes.':
      '<0>{0}</0> adresine 6 haneli bir kod gönderdik. 10 dakika boyunca geçerli.',
    'We sent a new code. Earlier ones no longer work':
      'Yeni bir kod gönderdik. Öncekiler artık çalışmıyor',
    'We sent a new code. Earlier ones no longer work.':
      'Yeni bir kod gönderdik. Öncekiler artık çalışmıyor.',
    Welcome: 'Hoş geldiniz',
    'We’ll send a code to <0>{0}</0>.': '<0>{0}</0> adresine bir kod göndereceğiz.',
    'We’ve sent several codes recently, so we’re pausing for a while to protect the inbox. Use the newest code you got, or try again in an hour.':
      'Son zamanlarda birkaç kod gönderdik; gelen kutusunu korumak için bir süre ara veriyoruz. Aldığınız en yeni kodu kullanın ya da bir saat sonra yeniden deneyin.',
    When: 'Ne zaman',
    'When your provider announces a new certificate, paste it here: both are accepted, so sign-in keeps working when it switches. Owners get an email 30, 7 and 1 days before the certificates expire.':
      'Sağlayıcınız yeni bir sertifika duyurduğunda onu buraya yapıştırın: ikisi de kabul edilir, böylece geçiş yapıldığında giriş çalışmaya devam eder. Sahipler sertifikaların süresi dolmadan 30, 7 ve 1 gün önce e-posta alır.',
    'Who may use it': 'Kimler kullanabilir',
    Withdraw: 'Geri al',
    'Work email address': 'İş e-posta adresi',
    'Working: last delivered {0}': 'Çalışıyor: son gönderim {0}',
    'Write (read-and-write keys)': 'Yazma (okuma ve yazma anahtarları)',
    'Wrong email code': 'Yanlış e-posta kodu',
    You: 'Siz',
    'You allowed {0} to use your 2earl account.':
      '{0} uygulamasının 2earl hesabınızı kullanmasına izin verdiniz.',
    'You become a member of “{0}”, which sees your name and address.':
      'Adınızı ve adresinizi gören “{0}” kurumunun üyesi olursunuz.',
    'You become its owner. Then invite people by email; each one joins with their own 2earl account. To have someone else own it, invite them to set it up from the admin pages instead.':
      'Kurumun sahibi siz olursunuz. Ardından kişileri e-postayla davet edin; her biri kendi 2earl hesabıyla katılır. Sahibinin başka biri olmasını istiyorsanız, onu bunun yerine yönetim sayfalarından kurumu kurmaya davet edin.',
    'You can change the name later in the organization’s settings.':
      'Adı daha sonra kurumun ayarlarından değiştirebilirsiniz.',
    'You can create a new account at any time. This is the last email you get from us about this account.':
      'İstediğiniz zaman yeni bir hesap oluşturabilirsiniz. Bu hesapla ilgili bizden aldığınız son e-posta budur.',
    'You can disconnect this app at any time in your account.':
      'Bu uygulamanın bağlantısını hesabınızdan istediğiniz zaman kesebilirsiniz.',
    'You can manage its members, or hand ownership to someone else':
      'Üyelerini yönetebilir ya da sahipliği başka birine devredebilirsiniz',
    'You can manage its members, or hand ownership to someone else.':
      'Üyelerini yönetebilir ya da sahipliği başka birine devredebilirsiniz.',
    'You can no longer sign in to 2earl with codes sent to {0}.':
      'Artık {0} adresine gönderilen kodlarla 2earl’e giriş yapamazsınız.',
    'You can no longer sign in to 2earl with sign-in with {0}.':
      'Artık {0} ile 2earl’e giriş yapamazsınız.',
    'You can no longer sign in to 2earl with the Google account {0}.':
      'Artık {0} Google hesabıyla 2earl’e giriş yapamazsınız.',
    'You can no longer sign in with codes sent to {0}.':
      'Artık {0} adresine gönderilen kodlarla giriş yapamazsınız.',
    'You can no longer sign in with sign-in with {0}.': 'Artık {0} ile giriş yapamazsınız.',
    'You can no longer sign in with the Google account {0}.':
      'Artık {0} Google hesabıyla giriş yapamazsınız.',
    'You can now sign in to 2earl with codes sent to {0}.':
      'Artık {0} adresine gönderilen kodlarla 2earl’e giriş yapabilirsiniz.',
    'You can now sign in to 2earl with the Google account {0}.':
      'Artık {0} Google hesabıyla 2earl’e giriş yapabilirsiniz.',
    'You can now sign in with Google too': 'Artık Google ile de giriş yapabilirsiniz',
    'You can now sign in with Google too.': 'Artık Google ile de giriş yapabilirsiniz.',
    'You can now sign in with a code sent to that address too':
      'Artık o adrese gönderilen bir kodla da giriş yapabilirsiniz',
    'You can now sign in with a code sent to that address too.':
      'Artık o adrese gönderilen bir kodla da giriş yapabilirsiniz.',
    'You can now sign in with codes sent to {0}.':
      'Artık {0} adresine gönderilen kodlarla giriş yapabilirsiniz.',
    'You can now sign in with the Google account {0}.':
      'Artık {0} Google hesabıyla giriş yapabilirsiniz.',
    'You can see what it may do, and disconnect it at any time.':
      'Neler yapabileceğini görebilir ve bağlantısını istediğiniz zaman kesebilirsiniz.',
    'You can sign in again as usual; apps you use need to be connected again. If you didn’t expect this, ask the organization’s admins.':
      'Her zamanki gibi yeniden giriş yapabilirsiniz; kullandığınız uygulamaların yeniden bağlanması gerekir. Bunu beklemiyorduysanız kurumun yöneticilerine sorun.',
    'You can’t change your own account here.': 'Kendi hesabınızı burada değiştiremezsiniz.',
    'You can’t join it right now. The invitation still works until it expires':
      'Şu an katılamazsınız. Davet süresi dolana kadar geçerli olmaya devam eder',
    'You can’t join it right now. The invitation still works until it expires.':
      'Şu an katılamazsınız. Davet süresi dolana kadar geçerli olmaya devam eder.',
    'You can’t remove that address, leave the organization or delete the account yourself. You can still download your data.':
      'Bu adresi kaldıramaz, kurumdan ayrılamaz ya da hesabı kendiniz silemezsiniz. Verilerinizi yine de indirebilirsiniz.',
    'You chose a different Google account from the one you sign in to 2earl with. Nothing was deleted.':
      '2earl’e giriş yaptığınızdan farklı bir Google hesabı seçtiniz. Hiçbir şey silinmedi.',
    'You get this because you’re an owner of the organization.':
      'Bunu kurumun sahiplerinden biri olduğunuz için alıyorsunuz.',
    'You got this email because of your 2earl account, or because someone used this address with 2earl. 2earl never asks for a password or a code by email or phone.':
      'Bu e-postayı 2earl hesabınız nedeniyle ya da biri bu adresi 2earl’de kullandığı için aldınız. 2earl asla e-postayla veya telefonla parola ya da kod istemez.',
    'You joined the organization': 'Kuruma katıldınız',
    'You joined the organization.': 'Kuruma katıldınız.',
    'You left the organization': 'Kurumdan ayrıldınız',
    'You left the organization.': 'Kurumdan ayrıldınız.',
    'You signed up as <0>{0}</0>.': '<0>{0}</0> olarak kaydoldunuz.',
    'You stopped managing the accounts at the domain. They belong to their people again':
      'Alan adındaki hesapları yönetmeyi bıraktınız. Hesaplar yeniden sahiplerine ait',
    'You stopped managing the accounts at the domain. They belong to their people again.':
      'Alan adındaki hesapları yönetmeyi bıraktınız. Hesaplar yeniden sahiplerine ait.',
    'You were signed out everywhere': 'Her yerde oturumunuz kapatıldı',
    'You were signed out of 2earl everywhere': '2earl’de her yerde oturumunuz kapatıldı',
    'Your 2earl account ({0})': '2earl hesabınız ({0})',
    'Your 2earl account and everything in it were deleted, and every connected app was disconnected.':
      '2earl hesabınız ve içindeki her şey silindi, her bağlı uygulamanın bağlantısı kesildi.',
    'Your 2earl account is no longer staff: it can’t open the admin pages. The account itself is unchanged.':
      '2earl hesabınız artık ekipte değil: yönetim sayfalarını açamaz. Hesabın kendisi değişmedi.',
    'Your 2earl account is signed out in this browser.':
      '2earl hesabınızın bu tarayıcıdaki oturumu kapatıldı.',
    'Your 2earl account was deactivated': '2earl hesabınız devre dışı bırakıldı',
    'Your 2earl account was deleted': '2earl hesabınız silindi',
    'Your 2earl account was given the support role: you can see users and organizations and help them, but change little.':
      '2earl hesabınıza destek rolü verildi: kullanıcıları ve kurumları görebilir ve onlara yardım edebilirsiniz, ama çok az şeyi değiştirebilirsiniz.',
    'Your 2earl account was made an admin of 2earl: you can manage users, organizations and their setup invitations, and apps.':
      '2earl hesabınız 2earl yöneticisi yapıldı: kullanıcıları, kurumları ve kurulum davetlerini ve uygulamaları yönetebilirsiniz.',
    'Your 2earl account works again': '2earl hesabınız yeniden çalışıyor',
    'Your 2earl account, its link to Google and its sessions are gone, and connected apps no longer have access.':
      '2earl hesabınız, Google bağlantısı ve oturumları silindi; bağlı uygulamaların artık erişimi yok.',
    'Your 2earl staff role was removed': '2earl ekip rolünüz kaldırıldı',
    'Your account': 'Hesabınız',
    'Your account and everything it holds are deleted, here and in every 2earl service. You’ll confirm it on the next page.':
      'Hesabınız ve içindeki her şey burada ve her 2earl hizmetinde silinir. Bir sonraki sayfada onaylayacaksınız.',
    'Your account and its data are kept. If you think this is a mistake, ask the organization’s admins.':
      'Hesabınız ve verileri saklanır. Bunun bir hata olduğunu düşünüyorsanız kurumun yöneticilerine sorun.',
    'Your account and your organization': 'Hesabınız ve kurumunuz',
    'Your account can no longer open 2earl’s admin pages.':
      'Hesabınız artık 2earl’ün yönetim sayfalarını açamaz.',
    'Your account can open 2earl’s admin pages.':
      'Hesabınız 2earl’ün yönetim sayfalarını açabilir.',
    'Your account has a second factor. Use it to finish signing in.':
      'Hesabınızın ikinci bir doğrulama adımı var. Girişi tamamlamak için onu kullanın.',
    'Your account has an address at that domain. The next time you sign in, choose whether the organization manages your account, or keep it your own by removing that address from it.':
      'Hesabınızın o alan adında bir adresi var. Bir sonraki girişinizde hesabınızı kurumun yönetip yönetmeyeceğini seçin ya da o adresi hesaptan kaldırarak kendinize ait tutun.',
    'Your account is deleted': 'Hesabınız silindi',
    'Your account is deleted as soon as you confirm with Google. It can’t be restored.':
      'Hesabınız Google ile onayladığınız anda silinir. Geri getirilemez.',
    'Your account is deleted as soon as you confirm with a code we email you. It can’t be restored.':
      'Hesabınız size e-postayla gönderdiğimiz bir kodla onayladığınız anda silinir. Geri getirilemez.',
    'Your account is ready': 'Hesabınız hazır',
    'Your account needs a second factor to open the admin pages. If you didn’t expect this, tell 2earl at legal@2earl.com.':
      'Hesabınızın yönetim sayfalarını açmak için ikinci bir doğrulama adımına ihtiyacı var. Bunu beklemiyorduysanız legal@2earl.com adresinden 2earl’e bildirin.',
    'Your account signs in with <0>{0}</0>. “{1}” proved it controls that domain. Choose what happens to your account.':
      'Hesabınız <0>{0}</0> ile giriş yapıyor. “{1}” o alan adını kontrol ettiğini kanıtladı. Hesabınıza ne olacağını seçin.',
    'Your account was deactivated': 'Hesabınız devre dışı bırakıldı',
    'Your account was deleted': 'Hesabınız silindi',
    'Your account was not deleted': 'Hesabınız silinmedi',
    'Your account works again': 'Hesabınız yeniden çalışıyor',
    'Your data': 'Verileriniz',
    'Your device is signed in': 'Cihazınızda giriş yapıldı',
    'Your device stays signed out. You can close this page.':
      'Cihazınızda oturum kapalı kalır. Bu sayfayı kapatabilirsiniz.',
    'Your directory decides roles: members of a group marked admin are admins, of one marked auditor are auditors (admin wins), and everyone else it provisioned is a member. Owners never change':
      'Rollere dizininiz karar verir: yönetici olarak işaretlenmiş bir grubun üyeleri yönetici, denetçi olarak işaretlenmiş bir grubun üyeleri denetçidir (yönetici rolü önceliklidir); eklediği diğer herkes üyedir. Sahipler asla değişmez',
    'Your directory decides roles: members of a group marked admin are admins, of one marked auditor are auditors (admin wins), and everyone else it provisioned is a member. Owners never change.':
      'Rollere dizininiz karar verir: yönetici olarak işaretlenmiş bir grubun üyeleri yönetici, denetçi olarak işaretlenmiş bir grubun üyeleri denetçidir (yönetici rolü önceliklidir); eklediği diğer herkes üyedir. Sahipler asla değişmez.',
    'Your directory decides this person’s role: change their groups there.':
      'Bu kişinin rolüne dizininiz karar verir: gruplarını orada değiştirin.',
    'Your fingerprint, face, screen lock or a security key. Passkeys only work on login.2earl.com, so they can’t be phished. A passkey also signs you in on its own, in one step.':
      'Parmak iziniz, yüzünüz, ekran kilidiniz ya da bir güvenlik anahtarı. Geçiş anahtarları yalnızca login.2earl.com’da çalıştığı için oltalamayla ele geçirilemez. Bir geçiş anahtarı sizi tek başına, tek adımda da giriş yaptırır.',
    'Your identity provider will sign with a new certificate around then. Paste the new one as the next signing certificate on Domains & SSO now: 2earl accepts both, so sign-in keeps working when the provider switches.':
      'Kimlik sağlayıcınız o sıralarda yeni bir sertifikayla imzalamaya başlayacak. Yenisini şimdi Alan adları ve SSO sayfasına sonraki imzalama sertifikası olarak yapıştırın: 2earl ikisini de kabul eder, böylece sağlayıcı geçiş yaptığında giriş çalışmaya devam eder.',
    'Your invitation. While sign-up is closed, signing in again needs a new one':
      'Davetiniz. Kayıt kapalıyken yeniden giriş yapmak için yeni bir davet gerekir',
    'Your name <0>optional, shown on your account and to people you share with</0>':
      'Adınız <0>isteğe bağlı; hesabınızda ve paylaştığınız kişilere gösterilir</0>',
    'Your name and email address ({0}), and how you sign in':
      'Adınız ve e-posta adresiniz ({0}) ve nasıl giriş yaptığınız',
    'Your organization doesn’t allow this app': 'Kurumunuz bu uygulamaya izin vermiyor',
    'Your organization manages accounts at your address’s domain':
      'Kurumunuz adresinizin alan adındaki hesapları yönetiyor',
    'Your organization manages this account': 'Bu hesabı kurumunuz yönetiyor',
    'Your organizations': 'Kurumlarınız',
    'Your own invitation': 'Kendi davetiniz',
    'Your ownership of “{0}”: {1} becomes its owner':
      '“{0}” kurumundaki sahipliğiniz: {1} kurumun sahibi olur',
    'Your role can’t do that. Ask an admin.': 'Rolünüz bunu yapamaz. Bir yöneticiye sorun.',
    'Your sign-in code': 'Giriş kodunuz',
    'Your staff role was removed': 'Ekip rolünüz kaldırıldı',
    'You’re 2earl support': '2earl destek ekibindesiniz',
    'You’re a 2earl admin': '2earl yöneticisisiniz',
    'You’re in 50 organizations, the most an account can be in. Leave one first':
      '50 kurumdasınız; bir hesabın olabileceği en fazla sayı bu. Önce birinden ayrılın',
    'You’re in 50 organizations, the most an account can be in. Leave one first.':
      '50 kurumdasınız; bir hesabın olabileceği en fazla sayı bu. Önce birinden ayrılın.',
    'You’re in too many organizations': 'Çok fazla kurumdasınız',
    'You’re invited to set up an organization and manage it.':
      'Bir kurum kurmaya ve onu yönetmeye davet edildiniz.',
    'You’re not in an organization yet. Accept an invitation someone sends you. Organizations are set up by invitation from 2earl.':
      'Henüz bir kurumda değilsiniz. Size gönderilen bir daveti kabul edin. Kurumlar 2earl’ün davetiyle kurulur.',
    'You’re not in an organization yet. Create one, or invite someone to set one up from the admin pages.':
      'Henüz bir kurumda değilsiniz. Bir tane oluşturun ya da yönetim sayfalarından birini kurum kurmaya davet edin.',
    'You’re now an admin at 2earl': 'Artık 2earl’de yöneticisiniz',
    'You’re now an owner': 'Artık sahipsiniz',
    'You’re now an owner of an organization on 2earl': 'Artık 2earl’de bir kurumun sahibisiniz',
    'You’re now an owner of the organization “{0}”, because its only owner deleted their 2earl account':
      'Tek sahibi 2earl hesabını sildiği için artık “{0}” kurumunun sahibisiniz',
    'You’re now an owner of the organization “{0}”, because its only owner deleted their 2earl account.':
      'Tek sahibi 2earl hesabını sildiği için artık “{0}” kurumunun sahibisiniz.',
    'You’re now an owner of “{0}”': 'Artık “{0}” kurumunun sahibisiniz',
    'You’re now an owner of “{0}”.': 'Artık “{0}” kurumunun sahibisiniz.',
    'You’re now support at 2earl': 'Artık 2earl destek ekibindesiniz',
    'You’re signed in as {0}, which doesn’t sign in with {1}. Sign in with the account that uses that address, or add the address to this account first.':
      '{0} olarak giriş yaptınız; bu hesap {1} ile giriş yapmıyor. O adresi kullanan hesapla giriş yapın ya da önce adresi bu hesaba ekleyin.',
    'You’re signed out': 'Çıkış yaptınız',
    'You’re the only owner. Make someone else an owner first, or delete the organization.':
      'Tek sahip sizsiniz. Önce başka birini sahip yapın ya da kurumu silin.',
    'You’re the only owner. To leave, make someone else an owner first, or delete the organization.':
      'Tek sahip sizsiniz. Ayrılmak için önce başka birini sahip yapın ya da kurumu silin.',
    'You’ve sent {0} invitations today, the most for one day. Try again tomorrow.':
      'Bugün {0} davet gönderdiniz; bir gün için en fazla bu kadar. Yarın yeniden deneyin.',
    'a code by email': 'e-postayla kod',
    'a passkey': 'bir geçiş anahtarıyla',
    'added a group': 'bir grup ekledi',
    'added a second factor': 'ikinci doğrulama adımı ekledi',
    'added a way to sign in': 'bir giriş yolu ekledi',
    'added someone': 'birini ekledi',
    'added the domain {0}': '{0} alan adını ekledi',
    'added {0}': '{0} kişisini ekledi',
    admin: 'yönetici',
    'allowed an app': 'bir uygulamaya izin verdi',
    'allowed any app again': 'yeniden her uygulamaya izin verdi',
    'allowed only chosen apps for managed accounts':
      'yönetilen hesaplar için yalnızca seçilen uygulamalara izin verdi',
    'an email code': 'bir e-posta koduyla',
    'as {0} on {1}': '{1} tarihinde {0} olarak',
    auditor: 'denetçi',
    'authenticator app': 'doğrulama uygulaması',
    'became an owner, after the only owner deleted their account':
      'tek sahip hesabını sildikten sonra sahip oldu',
    'by {0}': 'davet eden: {0}',
    'changed a group': 'bir grubu değiştirdi',
    'changed the OpenID Connect single sign-on settings (who can sign in as your people)':
      'OpenID Connect çoklu oturum açma ayarlarını değiştirdi (kimlerin sizin kişileriniz olarak giriş yapabileceğini)',
    'changed the SAML single sign-on settings (who can sign in as your people)':
      'SAML çoklu oturum açma ayarlarını değiştirdi (kimlerin sizin kişileriniz olarak giriş yapabileceğini)',
    'changed the audit stream': 'denetim akışını değiştirdi',
    'changed the security rules for managed accounts':
      'yönetilen hesapların güvenlik kurallarını değiştirdi',
    'changed where the activity log is streamed':
      'etkinlik kaydının nereye aktarıldığını değiştirdi',
    'confirmed a second factor': 'ikinci doğrulama adımını onayladı',
    'connected an app': 'bir uygulama bağladı',
    'created a directory sync (SCIM) token': 'bir dizin eşitleme (SCIM) token’ı oluşturdu',
    'created a directory sync token': 'bir dizin eşitleme token’ı oluşturdu',
    'created a managed account for someone': 'biri için yönetilen bir hesap oluşturdu',
    'created a managed account for {0}': '{0} için yönetilen bir hesap oluşturdu',
    'created the API key “{0}” (read and write)': '“{0}” API anahtarını oluşturdu (okuma ve yazma)',
    'created the API key “{0}” (read)': '“{0}” API anahtarını oluşturdu (okuma)',
    'created the organization': 'kurumu oluşturdu',
    'created {0}': '{0} tarihinde oluşturuldu',
    'deactivated an account': 'bir hesabı devre dışı bıraktı',
    'deactivated {0}': '{0} hesabını devre dışı bıraktı',
    'declined an invitation': 'bir daveti reddetti',
    'deleted a managed account': 'yönetilen bir hesabı sildi',
    'deleted a managed account, 30 days after the directory removed it':
      'dizin kaldırdıktan 30 gün sonra yönetilen bir hesabı sildi',
    'deleted account': 'silinmiş hesap',
    'deprovisioned a person': 'bir kişiyi kaldırdı',
    'disconnected an app': 'bir uygulamanın bağlantısını kesti',
    'downloaded the audit log': 'denetim kaydını indirdi',
    'downloaded their data': 'verilerini indirdi',
    'downloaded {0} days of the audit log': 'denetim kaydının {0} günlük kısmını indirdi',
    'e.g. Checked with the publisher on …': 'ör. Yayıncıyla … tarihinde kontrol edildi',
    'e.g. MacBook, YubiKey': 'ör. MacBook, YubiKey',
    'e.g. Prompt share backup server': 'ör. Prompt share yedek sunucusu',
    'email code': 'e-posta kodu',
    'ended a session': 'bir oturumu sonlandırdı',
    'entered a wrong second-factor code': 'yanlış bir ikinci adım kodu girdi',
    'failed to sign in': 'giriş yapamadı',
    'from {0}': 'kaynak: {0}',
    'got a managed account': 'yönetilen bir hesap aldı',
    'invited someone as {0}': 'birini {0} olarak davet etti',
    'invited {0}': '{0} tarihinde davet edildi',
    'invited {0} by {1}': '{0} tarihinde {1} tarafından davet edildi',
    'joined as {0}': '{0} olarak katıldı',
    'joined {0}': '{0} tarihinde katıldı',
    'kept their account personal': 'hesabını kişisel tuttu',
    'last sign-in {0}': 'son giriş {0}',
    'last used {0}': 'son kullanım {0}',
    'left the organization': 'kurumdan ayrıldı',
    'lost access to an app': 'bir uygulamaya erişimini kaybetti',
    'lost access to an app that isn’t allowed': 'izin verilmeyen bir uygulamaya erişimini kaybetti',
    'made the members of “{0}” admins': '“{0}” grubunun üyelerini yönetici yaptı',
    'made the members of “{0}” auditors': '“{0}” grubunun üyelerini denetçi yaptı',
    'made their account a managed account': 'hesabını yönetilen hesap yaptı',
    'made {0} a member': '{0} kişisini üye yaptı',
    'made {0} admin': '{0} kişisini yönetici yaptı',
    'made {0} an admin': '{0} kişisini yönetici yaptı',
    'made {0} an auditor': '{0} kişisini denetçi yaptı',
    'made {0} auditor': '{0} kişisini denetçi yaptı',
    'made {0} member': '{0} kişisini üye yaptı',
    'made {0} owner': '{0} kişisini sahip yaptı',
    'made {0} {1}': '{0} kişisini {1} yaptı',
    'managed by {0}': '{0} tarafından yönetiliyor',
    member: 'üye',
    'never signed in': 'hiç giriş yapmadı',
    'never used': 'hiç kullanılmadı',
    'no domains': 'alan adı yok',
    'no second factor': 'ikinci doğrulama adımı yok',
    none: 'yok',
    or: 'ya da',
    owner: 'sahip',
    'owners: {0}': 'sahipler: {0}',
    'provisioned a person': 'bir kişi ekledi',
    'reactivated an account': 'bir hesabı yeniden etkinleştirdi',
    'reactivated the organization': 'kurumu yeniden etkinleştirdi',
    'reactivated {0}': '{0} hesabını yeniden etkinleştirdi',
    'removed a former member': 'eski bir üyeyi çıkardı',
    'removed a group': 'bir grubu kaldırdı',
    'removed a second factor': 'bir doğrulama adımını kaldırdı',
    'removed a way to sign in': 'bir giriş yolunu kaldırdı',
    'removed an account: deactivated, deleted in 30 days':
      'bir hesabı kaldırdı: devre dışı bırakıldı, 30 gün içinde silinecek',
    'removed an allowed app': 'izin verilen bir uygulamayı kaldırdı',
    'removed someone': 'birini çıkardı',
    'removed the audit stream': 'denetim akışını kaldırdı',
    'removed the domain {0}': '{0} alan adını kaldırdı',
    'removed {0}': '{0} kişisini çıkardı',
    'removed {0}: deactivated, deleted in 30 days':
      '{0} hesabını kaldırdı: devre dışı bırakıldı, 30 gün içinde silinecek',
    'renamed the organization': 'kurumun adını değiştirdi',
    'required single sign-on for managed accounts':
      'yönetilen hesaplar için çoklu oturum açmayı zorunlu tuttu',
    'revoked a directory sync token': 'bir dizin eşitleme token’ını iptal etti',
    'revoked an API key': 'bir API anahtarını iptal etti',
    'saved OpenID Connect single sign-on, off':
      'OpenID Connect çoklu oturum açmayı kaydetti, kapalı',
    'saved OpenID Connect single sign-on, on': 'OpenID Connect çoklu oturum açmayı kaydetti, açık',
    'saved, turned off, single sign-on': 'çoklu oturum açmayı kaydetti ve kapattı',
    'second factor: {0}': 'ikinci doğrulama adımı: {0}',
    'security rules set': 'güvenlik kuralları belirlendi',
    'sent again {0}': '{0} yeniden gönderildi',
    'set up the organization from 2earl’s invitation': 'kurumu 2earl’ün davetiyle kurdu',
    'signed an account out everywhere': 'bir hesabın her yerdeki oturumunu kapattı',
    'signed in': 'giriş yaptı',
    'signed in with a passkey': 'geçiş anahtarıyla giriş yaptı',
    'signed in with an email code': 'e-posta koduyla giriş yaptı',
    'signed in with single sign-on': 'çoklu oturum açmayla giriş yaptı',
    'signed in with {0}': '{0} ile giriş yaptı',
    'signed out': 'çıkış yaptı',
    'signed {0} out everywhere': '{0} hesabının her yerdeki oturumunu kapattı',
    'signs in with Google and email code': 'Google ve e-posta koduyla giriş yapıyor',
    'signs in with email code': 'e-posta koduyla giriş yapıyor',
    'signs in with {0}': '{0} ile giriş yapıyor',
    'single sign-on': 'çoklu oturum açmayla',
    'some managed accounts became personal again': 'bazı yönetilen hesaplar yeniden kişisel oldu',
    'staff opened the organization to help (members, domains, activity)':
      'ekibi yardım için kurumu açtı (üyeler, alan adları, etkinlik)',
    'started managing the accounts at {0}': '{0} adresindeki hesapları yönetmeye başladı',
    'stopped giving the members of “{0}” a role': '“{0}” grubunun üyelerine rol vermeyi bıraktı',
    'stopped managing the accounts at {0}': '{0} adresindeki hesapları yönetmeyi bıraktı',
    'stopped requiring single sign-on for managed accounts':
      'yönetilen hesaplar için çoklu oturum açmayı zorunlu tutmayı bıraktı',
    'stopped streaming the activity log': 'etkinlik kaydını aktarmayı durdurdu',
    'suggested name “{0}”': 'önerilen ad “{0}”',
    'suspended the organization': 'kurumu askıya aldı',
    'told the owners that single sign-on’s certificate expires in {0} day':
      'sahiplere çoklu oturum açma sertifikasının süresinin {0} gün içinde dolacağını bildirdi',
    'told the owners that single sign-on’s certificate expires in {0} days':
      'sahiplere çoklu oturum açma sertifikasının süresinin {0} gün içinde dolacağını bildirdi',
    'told the owners that single sign-on’s certificate has expired':
      'sahiplere çoklu oturum açma sertifikasının süresinin dolduğunu bildirdi',
    'told the owners that single sign-on’s client secret expires in {0} day':
      'sahiplere çoklu oturum açma istemci sırrının süresinin {0} gün içinde dolacağını bildirdi',
    'told the owners that single sign-on’s client secret expires in {0} days':
      'sahiplere çoklu oturum açma istemci sırrının süresinin {0} gün içinde dolacağını bildirdi',
    'told the owners that single sign-on’s client secret has expired':
      'sahiplere çoklu oturum açma istemci sırrının süresinin dolduğunu bildirdi',
    'took new SAML signing certificates from your identity provider’s metadata URL':
      'kimlik sağlayıcınızın meta veri adresinden yeni SAML imzalama sertifikaları aldı',
    'took new signing certificates from the identity provider’s metadata':
      'kimlik sağlayıcının meta verisinden yeni imzalama sertifikaları aldı',
    'turned OpenID Connect single sign-on off': 'OpenID Connect çoklu oturum açmayı kapattı',
    'turned SAML single sign-on off': 'SAML çoklu oturum açmayı kapattı',
    'turned on single sign-on': 'çoklu oturum açmayı açtı',
    'until {0}': '{0} tarihine kadar',
    'updated a person': 'bir kişiyi güncelledi',
    'used a recovery code': 'bir kurtarma kodu kullandı',
    'verified the domain {0}': '{0} alan adını doğruladı',
    'was locked out after wrong second-factor codes':
      'yanlış ikinci adım kodlarından sonra kilitlendi',
    'was refused or declined an app': 'bir uygulama reddedildi ya da uygulamayı reddetti',
    'was refused sign-in': 'girişi reddedildi',
    'was refused sign-in ({0})': 'girişi reddedildi ({0})',
    'withdrew an invitation': 'bir daveti geri aldı',
    '{0} ({1}) changed the OpenID Connect single sign-on settings (who can sign in as your people) in “{2}”.':
      '{0} ({1}), “{2}” kurumunda OpenID Connect çoklu oturum açma ayarlarını (kimlerin sizin kişileriniz olarak giriş yapabileceğini) değiştirdi.',
    '{0} ({1}) changed the OpenID Connect single sign-on settings (who can sign in as your people).':
      '{0} ({1}), OpenID Connect çoklu oturum açma ayarlarını (kimlerin sizin kişileriniz olarak giriş yapabileceğini) değiştirdi.',
    '{0} ({1}) changed the SAML single sign-on settings (who can sign in as your people) in “{2}”.':
      '{0} ({1}), “{2}” kurumunda SAML çoklu oturum açma ayarlarını (kimlerin sizin kişileriniz olarak giriş yapabileceğini) değiştirdi.',
    '{0} ({1}) changed the SAML single sign-on settings (who can sign in as your people).':
      '{0} ({1}), SAML çoklu oturum açma ayarlarını (kimlerin sizin kişileriniz olarak giriş yapabileceğini) değiştirdi.',
    '{0} ({1}) changed the security rules for managed accounts in “{2}”.':
      '{0} ({1}), “{2}” kurumunda yönetilen hesapların güvenlik kurallarını değiştirdi.',
    '{0} ({1}) changed the security rules for managed accounts.':
      '{0} ({1}), yönetilen hesapların güvenlik kurallarını değiştirdi.',
    '{0} ({1}) changed where the activity log is streamed in “{2}”.':
      '{0} ({1}), “{2}” kurumunda etkinlik kaydının nereye aktarıldığını değiştirdi.',
    '{0} ({1}) changed where the activity log is streamed.':
      '{0} ({1}), etkinlik kaydının nereye aktarıldığını değiştirdi.',
    '{0} ({1}) changed {2} ({3}) from {4} to {5} in “{6}”.':
      '{0} ({1}), “{6}” kurumunda {2} ({3}) kişisinin rolünü {4} rolünden {5} rolüne değiştirdi.',
    '{0} ({1}) changed {2} ({3}) from {4} to {5}.':
      '{0} ({1}), {2} ({3}) kişisinin rolünü {4} rolünden {5} rolüne değiştirdi.',
    '{0} ({1}) created a directory sync (SCIM) token in “{2}”.':
      '{0} ({1}), “{2}” kurumunda bir dizin eşitleme (SCIM) token’ı oluşturdu.',
    '{0} ({1}) created a directory sync (SCIM) token.':
      '{0} ({1}), bir dizin eşitleme (SCIM) token’ı oluşturdu.',
    '{0} ({1}) created an API key “{2}” with read access in “{3}”.':
      '{0} ({1}), “{3}” kurumunda okuma erişimli “{2}” API anahtarını oluşturdu.',
    '{0} ({1}) created an API key “{2}” with read access.':
      '{0} ({1}), okuma erişimli “{2}” API anahtarını oluşturdu.',
    '{0} ({1}) created an API key “{2}” with read and write access in “{3}”.':
      '{0} ({1}), “{3}” kurumunda okuma ve yazma erişimli “{2}” API anahtarını oluşturdu.',
    '{0} ({1}) created an API key “{2}” with read and write access.':
      '{0} ({1}), okuma ve yazma erişimli “{2}” API anahtarını oluşturdu.',
    '{0} ({1}) invited you to join as a member.': '{0} ({1}) sizi üye olarak katılmaya davet etti.',
    '{0} ({1}) invited you to join as an admin.':
      '{0} ({1}) sizi yönetici olarak katılmaya davet etti.',
    '{0} ({1}) invited you to join as an auditor (read-only).':
      '{0} ({1}) sizi denetçi (salt okunur) olarak katılmaya davet etti.',
    '{0} ({1}) invited you to join the organization “{2}” on 2earl, as a member.':
      '{0} ({1}) sizi 2earl’deki “{2}” kurumuna üye olarak katılmaya davet etti.',
    '{0} ({1}) invited you to join the organization “{2}” on 2earl, as an admin.':
      '{0} ({1}) sizi 2earl’deki “{2}” kurumuna yönetici olarak katılmaya davet etti.',
    '{0} ({1}) invited you to join the organization “{2}” on 2earl, as an auditor (read-only).':
      '{0} ({1}) sizi 2earl’deki “{2}” kurumuna denetçi (salt okunur) olarak katılmaya davet etti.',
    '{0} ({1}) invited {2} to join this organization as a member. Members can see who else is in the organization.':
      '{0} ({1}), {2} adresini bu kuruma üye olarak katılmaya davet etti. Üyeler kurumda başka kimlerin olduğunu görebilir.',
    '{0} ({1}) invited {2} to join this organization as an admin. Admins can invite people, remove members and admins, and change their roles.':
      '{0} ({1}), {2} adresini bu kuruma yönetici olarak katılmaya davet etti. Yöneticiler kişileri davet edebilir, üyeleri ve yöneticileri çıkarabilir ve rollerini değiştirebilir.',
    '{0} ({1}) invited {2} to join this organization as an auditor. Auditors see the members and the activity, and can download it, but can’t change anything.':
      '{0} ({1}), {2} adresini bu kuruma denetçi olarak katılmaya davet etti. Denetçiler üyeleri ve etkinliği görür ve indirebilir, ama hiçbir şeyi değiştiremez.',
    '{0} ({1}) made the directory group “{2}” admins in “{3}”.':
      '{0} ({1}), “{3}” kurumunda “{2}” dizin grubunu yönetici yaptı.',
    '{0} ({1}) made the directory group “{2}” admins.':
      '{0} ({1}), “{2}” dizin grubunu yönetici yaptı.',
    '{0} ({1}) made the directory group “{2}” auditors in “{3}”.':
      '{0} ({1}), “{3}” kurumunda “{2}” dizin grubunu denetçi yaptı.',
    '{0} ({1}) made the directory group “{2}” auditors.':
      '{0} ({1}), “{2}” dizin grubunu denetçi yaptı.',
    '{0} ({1}) made {2} ({3}) an admin in “{4}”.':
      '{0} ({1}), “{4}” kurumunda {2} ({3}) kişisini yönetici yaptı.',
    '{0} ({1}) made {2} ({3}) an admin.': '{0} ({1}), {2} ({3}) kişisini yönetici yaptı.',
    '{0} ({1}) made {2} ({3}) an auditor (reads the activity) in “{4}”.':
      '{0} ({1}), “{4}” kurumunda {2} ({3}) kişisini denetçi (etkinliği okur) yaptı.',
    '{0} ({1}) made {2} ({3}) an auditor (reads the activity).':
      '{0} ({1}), {2} ({3}) kişisini denetçi (etkinliği okur) yaptı.',
    '{0} ({1}) made {2} ({3}) an owner in “{4}”.':
      '{0} ({1}), “{4}” kurumunda {2} ({3}) kişisini sahip yaptı.',
    '{0} ({1}) made {2} ({3}) an owner.': '{0} ({1}), {2} ({3}) kişisini sahip yaptı.',
    '{0} ({1}) stopped managing accounts at {2} in “{3}”.':
      '{0} ({1}), “{3}” kurumunda {2} adresindeki hesapları yönetmeyi bıraktı.',
    '{0} ({1}) stopped managing accounts at {2}.':
      '{0} ({1}), {2} adresindeki hesapları yönetmeyi bıraktı.',
    '{0} ({1}) stopped streaming the activity log in “{2}”.':
      '{0} ({1}), “{2}” kurumunda etkinlik kaydını aktarmayı durdurdu.',
    '{0} ({1}) stopped streaming the activity log.':
      '{0} ({1}), etkinlik kaydını aktarmayı durdurdu.',
    '{0} ({1}) turned OpenID Connect single sign-on off in “{2}”.':
      '{0} ({1}), “{2}” kurumunda OpenID Connect çoklu oturum açmayı kapattı.',
    '{0} ({1}) turned OpenID Connect single sign-on off.':
      '{0} ({1}), OpenID Connect çoklu oturum açmayı kapattı.',
    '{0} ({1}) turned SAML single sign-on off in “{2}”.':
      '{0} ({1}), “{2}” kurumunda SAML çoklu oturum açmayı kapattı.',
    '{0} ({1}) turned SAML single sign-on off.': '{0} ({1}), SAML çoklu oturum açmayı kapattı.',
    '{0} ({1}) {2} in “{3}”': '{0} ({1}), “{3}” kurumunda: {2}',
    '{0} ({1}) {2} in “{3}”.': '{0} ({1}), “{3}” kurumunda: {2}.',
    '{0} account found. Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.':
      '{0} hesap bulundu. Askıya almak kullanıcının her yerdeki oturumunu kapatır ve uygulamalarının bağlantısını keser; yeniden etkinleştirmek tekrar giriş yapmasını sağlar.',
    '{0} account. Signing someone out everywhere ends every session and disconnects their apps; they can sign in again at once. Ask an admin to suspend or delete an account.':
      '{0} hesap. Birinin her yerdeki oturumunu kapatmak tüm oturumlarını sonlandırır ve uygulamalarının bağlantısını keser; hemen yeniden giriş yapabilir. Bir hesabı askıya almak veya silmek için bir yöneticiye başvurun.',
    '{0} account. Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.':
      '{0} hesap. Askıya almak kullanıcının her yerdeki oturumunu kapatır ve uygulamalarının bağlantısını keser; yeniden etkinleştirmek tekrar giriş yapmasını sağlar.',
    '{0} accounts found. Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.':
      '{0} hesap bulundu. Askıya almak kullanıcının her yerdeki oturumunu kapatır ve uygulamalarının bağlantısını keser; yeniden etkinleştirmek tekrar giriş yapmasını sağlar.',
    '{0} accounts. Signing someone out everywhere ends every session and disconnects their apps; they can sign in again at once. Ask an admin to suspend or delete an account.':
      '{0} hesap. Birinin her yerdeki oturumunu kapatmak tüm oturumlarını sonlandırır ve uygulamalarının bağlantısını keser; hemen yeniden giriş yapabilir. Bir hesabı askıya almak veya silmek için bir yöneticiye başvurun.',
    '{0} accounts. Suspending signs the user out everywhere and disconnects their apps; reactivating lets them sign in again.':
      '{0} hesap. Askıya almak kullanıcının her yerdeki oturumunu kapatır ve uygulamalarının bağlantısını keser; yeniden etkinleştirmek tekrar giriş yapmasını sağlar.',
    '{0} active · {1} without a 2earl account yet · {2} deactivated':
      '{0} etkin · {1} henüz 2earl hesabı olmayan · {2} devre dışı',
    '{0} can now act for you': '{0} artık sizin adınıza işlem yapabilir',
    '{0} confirms deleting your 2earl account': '{0}: 2earl hesabınızı silmeyi onaylama kodu',
    '{0} days': '{0} gün',
    '{0} deactivated the account it manages.': '{0}, yönettiği hesabı devre dışı bıraktı.',
    '{0} hours': '{0} saat',
    '{0} is your 2earl code': '2earl kodunuz: {0}',
    '{0} managed accounts became personal again': '{0} yönetilen hesap yeniden kişisel oldu',
    '{0} managed · {1} deactivated': '{0} yönetilen · {1} devre dışı',
    '{0} manages this account and allows it only from its own networks. Connect to one of them (for example your company’s VPN), then sign in again.':
      '{0} bu hesabı yönetiyor ve yalnızca kendi ağlarından kullanılmasına izin veriyor. Bunlardan birine bağlanın (örneğin şirketinizin VPN’i), ardından yeniden giriş yapın.',
    '{0} manages this account and asks you to sign in through its single sign-on. Choose “Sign in with your organization (SSO)” and enter your work address.':
      '{0} bu hesabı yönetiyor ve çoklu oturum açma hizmeti üzerinden giriş yapmanızı istiyor. “Kurumunuzla giriş yapın (SSO)” seçeneğini seçin ve iş adresinizi girin.',
    '{0} manages this account and doesn’t allow signing in this way. Use one it allows ({1}), or its single sign-on.':
      '{0} bu hesabı yönetiyor ve bu şekilde giriş yapılmasına izin vermiyor. İzin verdiği bir yolu ({1}) ya da çoklu oturum açma hizmetini kullanın.',
    '{0} member': '{0} üye',
    '{0} members': '{0} üye',
    '{0} now manages 2earl accounts at {1}':
      '{0} artık {1} adresindeki 2earl hesaplarını yönetiyor',
    '{0} of 10 unused. Use one if you can’t use your passkey or app. Creating new codes replaces the old ones.':
      '10 koddan {0} tanesi kullanılmadı. Geçiş anahtarınızı veya uygulamanızı kullanamazsanız birini kullanın. Yeni kodlar oluşturmak eskilerin yerini alır.',
    '{0} open invitations': '{0} açık davet',
    '{0} organizations. Open one to see its members and setup. Suspending one freezes it: members can only leave, and 2earl services stop seeing it.':
      '{0} kurum. Üyelerini ve kurulumunu görmek için birini açın. Askıya almak kurumu dondurur: üyeler yalnızca ayrılabilir ve 2earl hizmetleri onu artık görmez.',
    '{0} passkey': '{0} geçiş anahtarı',
    '{0} passkeys': '{0} geçiş anahtarı',
    '{0} reactivated your account.': '{0} hesabınızı yeniden etkinleştirdi.',
    '{0} signed you out and asks to sign you out of your 2earl account in this browser too.':
      '{0} oturumunuzu kapattı ve bu tarayıcıda 2earl hesabınızdan da çıkış yapmanızı istiyor.',
    '{0} signed you out on every device.': '{0} tüm cihazlarınızdaki oturumlarınızı kapattı.',
    '{0}. Only owners can rename it.': '{0}. Adını yalnızca sahipler değiştirebilir.',
    '{0}: activity': '{0}: etkinlik',
    '{0}: settings': '{0}: ayarlar',
    '{0}: single sign-on’s certificate expires on {1}':
      '{0}: çoklu oturum açma sertifikasının süresi {1} tarihinde doluyor',
    '{0}: single sign-on’s certificate has expired':
      '{0}: çoklu oturum açma sertifikasının süresi doldu',
    '{0}: single sign-on’s client secret expires on {1}':
      '{0}: çoklu oturum açma istemci sırrının süresi {1} tarihinde doluyor',
    '{0}: single sign-on’s client secret has expired':
      '{0}: çoklu oturum açma istemci sırrının süresi doldu',
    '· from {0}': '· kaynak: {0}',
    '“{0}” manages accounts at your address’s domain':
      '“{0}” adresinizin alan adındaki hesapları yönetiyor',
    '“{0}” manages this account and requires a passkey. Add one to continue.':
      '“{0}” bu hesabı yönetiyor ve geçiş anahtarını zorunlu tutuyor. Devam etmek için bir tane ekleyin.',
    '“{0}” manages this account and requires a second factor. Add one to continue.':
      '“{0}” bu hesabı yönetiyor ve ikinci bir doğrulama adımını zorunlu tutuyor. Devam etmek için bir tane ekleyin.',
    '“{0}” manages this account, so only it can delete it. Ask its admins. You can still download your data.':
      '“{0}” bu hesabı yönettiği için onu yalnızca o silebilir. Yöneticilerine sorun. Verilerinizi yine de indirebilirsiniz.',
    '“{0}” manages your 2earl account and deactivated it. You can’t sign in, and connected apps lost access.':
      '“{0}” 2earl hesabınızı yönetiyor ve onu devre dışı bıraktı. Giriş yapamazsınız ve bağlı uygulamalar erişimini kaybetti.',
    '“{0}” manages your 2earl account and signed it out on every device. Connected apps lost access too.':
      '“{0}” 2earl hesabınızı yönetiyor ve tüm cihazlardaki oturumlarını kapattı. Bağlı uygulamalar da erişimini kaybetti.',
    '“{0}” manages your account and allows only some apps. Ask its admins to allow this one.':
      '“{0}” hesabınızı yönetiyor ve yalnızca bazı uygulamalara izin veriyor. Yöneticilerinden buna izin vermelerini isteyin.',
    '“{0}” reactivated the 2earl account it manages. You can sign in again.':
      '“{0}” yönettiği 2earl hesabını yeniden etkinleştirdi. Yeniden giriş yapabilirsiniz.',
    '“{0}” requires a passkey. Add another one before removing this one.':
      '“{0}” geçiş anahtarını zorunlu tutuyor. Bunu kaldırmadan önce bir tane daha ekleyin.',
    '“{0}” requires a passkey. Use your passkey, or a recovery code.':
      '“{0}” geçiş anahtarını zorunlu tutuyor. Geçiş anahtarınızı ya da bir kurtarma kodunu kullanın.',
    '“{0}” requires a second factor. Add another one before removing this one.':
      '“{0}” ikinci doğrulama adımını zorunlu tutuyor. Bunu kaldırmadan önce bir tane daha ekleyin.',
    // Permissions and roles (DESIGN §4.32).
    'See the organization’s members': 'Kurumun üyelerini görme',
    'See and download the organization’s activity': 'Kurumun etkinliğini görme ve indirme',
    'Invite people and withdraw invitations': 'Kişileri davet etme ve davetleri geri çekme',
    'Change roles of members, auditors and admins, and remove them':
      'Üyelerin, denetçilerin ve yöneticilerin rollerini değiştirme ve onları çıkarma',
    'Make, unmake and remove owners': 'Sahip yapma, sahipliği kaldırma ve sahipleri çıkarma',
    'Rename and delete the organization': 'Kurumu yeniden adlandırma ve silme',
    'Open the admin area: people, organizations, the security log':
      'Yönetim alanını açma: kişiler, kurumlar, güvenlik kaydı',
    'Sign a person out everywhere': 'Bir kişinin her yerdeki oturumunu kapatma',
    'Send an organization setup invitation again': 'Kurum kurulum davetini yeniden gönderme',
    'Suspend, reactivate, reset a second factor and delete people':
      'Kişileri askıya alma, yeniden etkinleştirme, ikinci doğrulama adımını sıfırlama ve silme',
    'Open and close sign-up, and invite people to sign up':
      'Kaydı açma ve kapatma, kişileri kayda davet etme',
    'Create organizations and invite people to set them up':
      'Kurum oluşturma ve kişileri kurum kurmaya davet etme',
    'Suspend, reactivate and delete organizations':
      'Kurumları askıya alma, yeniden etkinleştirme ve silme',
    'Manage registered apps and resource servers':
      'Kayıtlı uygulamaları ve kaynak sunucularını yönetme',
    'Give, change and take staff roles, and act on other staff':
      'Personel rollerini verme, değiştirme ve geri alma, diğer personel üzerinde işlem yapma',
    'See the organization’s cases': 'Kurumun dosyalarını görme',
    'Add, change, confirm and withdraw cases, and upload files of cases':
      'Dosya ekleme, değiştirme, onaylama ve geri çekme, dosya listesi yükleme',
    'Manage API keys and webhooks, which act for the organization':
      'Kurum adına çalışan API anahtarlarını ve webhook’ları yönetme',
    'Open Emanet Merkez and settle identity reviews':
      'Emanet Merkez’i açma ve kimlik incelemelerini sonuçlandırma',
    'Change partners, agents and settings, confirm deliveries and move money in Emanet Merkez':
      'Emanet Merkez’de iş ortaklarını, görevlileri ve ayarları değiştirme, teslimleri onaylama ve para hareketi yapma',
    'Partner admin': 'İş ortağı yöneticisi',
    'Case manager': 'Dosya sorumlusu',
    Viewer: 'Görüntüleyen',
    'Merkez admin': 'Merkez yöneticisi',
    'Merkez reviewer': 'Merkez inceleyicisi',
    'See the organization’s roles in 2earl’s apps, and who holds them':
      'Kurumun 2earl uygulamalarındaki rollerini ve bunlara kimlerin sahip olduğunu görme',
    'Give and take roles in 2earl’s apps, up to what you hold yourself':
      '2earl uygulamalarında, kendi sahip olduklarınızı aşmadan rol verme ve geri alma',
    'Create, change and delete the organization’s own roles':
      'Kurumun kendi rollerini oluşturma, değiştirme ve silme',
    'Roles in apps': 'Uygulamalardaki roller',
    'What your people may do in 2earl’s apps. Each person’s role in the organization gives them a starting set; here you give more, to people, directory groups or service accounts, for good or for a number of days. You can give only roles whose permissions you hold yourself.':
      'Kişilerinizin 2earl uygulamalarında neler yapabileceği. Herkesin kurumdaki rolü bir başlangıç kümesi verir; burada kişilere, dizin gruplarına veya hizmet hesaplarına süresiz ya da belirli gün sayısı için daha fazlasını verirsiniz. Yalnızca izinlerine kendiniz sahip olduğunuz rolleri verebilirsiniz.',
    Roles: 'Roller',
    'Given roles': 'Verilen roller',
    'Nobody has been given a role here.': 'Burada henüz kimseye rol verilmedi.',
    Who: 'Kime',
    'For how many days (empty: until taken back)': 'Kaç gün için (boş: geri alınana kadar)',
    'Why (optional, kept with the role)': 'Neden (isteğe bağlı, rolle birlikte saklanır)',
    'Give role': 'Rol ver',
    'Create role': 'Rol oluştur',
    'Description (optional)': 'Açıklama (isteğe bağlı)',
    Permissions: 'İzinler',
    'Built in': 'Hazır',
    'Owners give it': 'Sahipler verir',
    Yours: 'Sizin',
    'Take back': 'Geri al',
    Person: 'Kişi',
    'Directory group': 'Dizin grubu',
    'Service account': 'Hizmet hesabı',
    'Service accounts': 'Hizmet hesapları',
    'Create service account': 'Hizmet hesabı oluştur',
    'Role given. It applies from their next request.':
      'Rol verildi. Bir sonraki isteklerinden itibaren geçerli.',
    'Role taken back. It ends at their next request.':
      'Rol geri alındı. Bir sonraki isteklerinde sona erer.',
    'Role created. Give it to people below.': 'Rol oluşturuldu. Aşağıdan kişilere verin.',
    'Role deleted, and taken back from everyone who had it.':
      'Rol silindi ve sahip olan herkesten geri alındı.',
    'You can’t give yourself a role. Ask another admin or owner.':
      'Kendinize rol veremezsiniz. Başka bir yöneticiye veya sahibe sorun.',
    'You can only give roles whose permissions you hold yourself.':
      'Yalnızca izinlerine kendiniz sahip olduğunuz rolleri verebilirsiniz.',
    'Only owners can give or take this role.': 'Bu rolü yalnızca sahipler verip geri alabilir.',
    'Your role in the organization doesn’t allow this.': 'Kurumdaki rolünüz buna izin vermiyor.',
    'They already have this role.': 'Bu role zaten sahipler.',
    'Service account deleted. Its tokens stop working within a minute.':
      'Hizmet hesabı silindi. Belirteçleri bir dakika içinde çalışmaz hale gelir.',
    'Roles in 2earl’s apps': '2earl uygulamalarındaki roller',
    'Admins and support get each app’s default staff role. Give more here, for one app: what it allows is listed with each role. A role ends when it runs out, when you take it back, or when the person leaves staff.':
      'Yöneticiler ve destek her uygulamanın varsayılan personel rolünü alır. Burada tek bir uygulama için daha fazlasını verin: her rolün neye izin verdiği yanında yazar. Rol, süresi dolduğunda, geri aldığınızda veya kişi personelden ayrıldığında sona erer.',
    'No app roles given beyond what staff roles give.':
      'Personel rollerinin verdiklerinin ötesinde uygulama rolü verilmedi.',
    'Role taken back.': 'Rol geri alındı.',
  },
};
