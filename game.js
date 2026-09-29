'use strict';

/* EDUCA- — versão infantil profissional
   8 matérias × 50 níveis × 5 perguntas.
   Cada pergunta possui ID único. O progresso guarda os IDs já utilizados por matéria,
   impedindo repetição até o banco inteiro daquela matéria ser consumido.
*/

const SUBJECTS={
 matematica:{name:'Matemática',icon:'➗',desc:'Números, lógica e desafios'},
 portugues:{name:'Português',icon:'📖',desc:'Leitura, gramática e escrita'},
 ciencias:{name:'Ciências',icon:'🔬',desc:'Vida, corpo, matéria e universo'},
 historia:{name:'História',icon:'🏛️',desc:'Povos, fatos e transformações'},
 geografia:{name:'Geografia',icon:'🌎',desc:'Mapas, natureza e sociedade'},
 ingles:{name:'Inglês',icon:'🇺🇸',desc:'Vocabulário e comunicação'},
 informatica:{name:'Informática',icon:'💻',desc:'Tecnologia, lógica e internet'},
 artes:{name:'Artes',icon:'🎨',desc:'Criação, cultura e expressão'}
};
const TOTAL_LEVELS=50, QUESTIONS_PER_LEVEL=5;
let currentUser='',currentSubject='',currentLevel=1,currentQuestions=[],questionIndex=0,levelCorrect=0,currentMissionIsAI=false;
let audioCtx=null;
let currentKey=null;
let currentProgress={xp:0,playerLevel:1,completedLevels:{},usedQuestions:{}};
const $=id=>document.getElementById(id);
const escapeKey=s=>String(s).replace(/[^a-zA-Z0-9_-]/g,'_');
const escapeHtml=s=>String(s).replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
const DEFAULT_PROGRESS=()=>({xp:0,playerLevel:1,completedLevels:{},usedQuestions:{},coins:0,ownedSkins:[],ownedItems:[],equippedSkin:'default',equippedItem:'none',achievements:{},stats:{}});

/* ---------- CONTA REAL NO SERVIDOR ---------- */
const API_BASE=(window.EDUCA_API||'').replace(/\/$/,'');
let authToken=sessionStorage.getItem('educaAuthToken')||'';
let accountSalt='';
let pendingEmail='';
async function api(path,options={}){
 const headers=Object.assign({'Content-Type':'application/json'},options.headers||{});
 if(authToken)headers.Authorization=`Bearer ${authToken}`;
 const res=await fetch(API_BASE+path,Object.assign({},options,{headers}));
 let data={};try{data=await res.json()}catch{}
 if(!res.ok){const err=new Error(data.error||'Erro de comunicação com o servidor.');err.status=res.status;err.data=data;throw err}
 return data;
}
async function registerRemote(username,email,password){return api('/api/auth/register',{method:'POST',body:JSON.stringify({username,email,password})})}
async function verifyRemote(email,code){const data=await api('/api/auth/verify',{method:'POST',body:JSON.stringify({email,code})});authToken=data.token;accountSalt=data.salt;sessionStorage.setItem('educaAuthToken',authToken);return data}
async function loginRemote(identifier,password){const data=await api('/api/auth/login',{method:'POST',body:JSON.stringify({identifier,password})});authToken=data.token;accountSalt=data.salt;sessionStorage.setItem('educaAuthToken',authToken);return data}
async function logoutRemote(){if(!authToken)return;try{await api('/api/auth/logout',{method:'POST'})}catch{}authToken='';sessionStorage.removeItem('educaAuthToken')}
async function requestPasswordReset(email){return api('/api/auth/forgot-password',{method:'POST',body:JSON.stringify({email})})}
async function resetPasswordRemote(email,code,password){const data=await api('/api/auth/reset-password',{method:'POST',body:JSON.stringify({email,code,password})});authToken=data.token;accountSalt=data.salt;sessionStorage.setItem('educaAuthToken',authToken);return data}
async function syncProgressRemote(){if(!authToken||!currentKey)return;try{const encrypted=await encryptProgress(currentProgress,currentKey);await api('/api/progress',{method:'PUT',body:JSON.stringify({progress:encrypted})})}catch(e){console.warn('Falha ao sincronizar progresso',e)}}
async function openServerProgress(blob,key){if(!blob)return DEFAULT_PROGRESS();try{return Object.assign(DEFAULT_PROGRESS(),await decryptProgress(typeof blob==='string'?JSON.parse(blob):blob,key))}catch{return DEFAULT_PROGRESS()}}

function showScreen(id){document.querySelectorAll('.screen').forEach(s=>s.classList.remove('active'));const el=$(id);if(el){el.classList.add('active');window.scrollTo({top:0,behavior:'smooth'})}}
function accountKey(name=currentUser){return `educaAccount_${escapeKey(name)}`}
function getAccount(name){try{return JSON.parse(localStorage.getItem(accountKey(name))||'null')}catch{return null}}
function normalizeName(v){return v.trim().replace(/\s+/g,' ').slice(0,20)}
function shuffle(arr){return [...arr].sort(()=>Math.random()-.5)}
function unique(arr){return [...new Set(arr.map(String))]}

/* ---------- CONTAS E DADOS PROTEGIDOS ----------
   O site não guarda a senha em texto puro. A senha gera uma chave PBKDF2;
   o progresso é cifrado com AES-GCM. Isso protege os dados salvos neste navegador.
*/
const encoder=new TextEncoder(),decoder=new TextDecoder();
function bytesToB64(bytes){let bin='';bytes.forEach(b=>bin+=String.fromCharCode(b));return btoa(bin)}
function b64ToBytes(str){const bin=atob(str);return Uint8Array.from(bin,c=>c.charCodeAt(0))}
function randomB64(size=16){return bytesToB64(crypto.getRandomValues(new Uint8Array(size)))}
async function deriveKey(password,saltB64){
 const material=await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits','deriveKey']);
 const salt=b64ToBytes(saltB64);
 return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:150000,hash:'SHA-256'},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function makeVerifier(password,saltB64){
 const key=await deriveKey(password,saltB64);
 const bits=await crypto.subtle.exportKey('raw',key);
 return bytesToB64(new Uint8Array(bits));
}
async function encryptProgress(progress,key){
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const data=encoder.encode(JSON.stringify(progress));
 const cipher=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,data);
 return {iv:bytesToB64(iv),data:bytesToB64(new Uint8Array(cipher))};
}
async function decryptProgress(saved,key){
 const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64ToBytes(saved.iv)},key,b64ToBytes(saved.data));
 return JSON.parse(decoder.decode(plain));
}
function getProgress(){return currentProgress}
function saveProgress(p){
 currentProgress=Object.assign(DEFAULT_PROGRESS(),p);
 if(!currentKey||!currentUser)return;
 encryptProgress(currentProgress,currentKey).then(async encrypted=>{
  const account=getAccount(currentUser);
  if(account){account.progress=encrypted;localStorage.setItem(accountKey(currentUser),JSON.stringify(account))}
  if(authToken)await syncProgressRemote();
 }).catch(()=>toast('⚠️ Não foi possível proteger os dados agora.'));
}

async function createAccount(name,password,initialProgress=DEFAULT_PROGRESS()){
 const salt=randomB64(16),key=await deriveKey(password,salt),verifier=await makeVerifier(password,salt);
 const account={version:2,username:name,salt,verifier,createdAt:Date.now(),progress:await encryptProgress(initialProgress,key)};
 localStorage.setItem(accountKey(name),JSON.stringify(account));
 return {account,key,progress:initialProgress};
}
async function authenticate(name,password){
 const account=getAccount(name);
 if(!account)return {ok:false,reason:'not-found'};
 if(account.version===2&&account.salt&&account.verifier){
  const key=await deriveKey(password,account.salt);
  const verifier=await makeVerifier(password,account.salt);
  if(verifier!==account.verifier)return {ok:false,reason:'wrong-password'};
  let progress=DEFAULT_PROGRESS();
  if(account.progress){
   try{progress=Object.assign(DEFAULT_PROGRESS(),await decryptProgress(account.progress,key))}catch{return {ok:false,reason:'data-error'}}
  }
  return {ok:true,key,progress};
 }
 /* Migração de contas antigas que tinham a senha salva em texto puro. */
 if(account.password===password){
  let legacyProgress=DEFAULT_PROGRESS();
  try{
   const old=JSON.parse(localStorage.getItem(`educaProgress_${escapeKey(name)}`)||'null');
   if(old)legacyProgress=Object.assign(DEFAULT_PROGRESS(),old);
  }catch{}
  const created=await createAccount(name,password,legacyProgress);
  try{localStorage.removeItem(`educaProgress_${escapeKey(name)}`)}catch{}
  return {ok:true,key:created.key,progress:legacyProgress};
 }
 return {ok:false,reason:'wrong-password'};
}

/* ---------- ÁUDIO: Web Audio, sem arquivos externos ---------- */
function sound(type){
 try{
  audioCtx??=new(window.AudioContext||window.webkitAudioContext)();
  if(audioCtx.state==='suspended')audioCtx.resume();
  const sets={
   click:[[330,.06]],correct:[[523,.08],[659,.08],[784,.12]],wrong:[[210,.09],[155,.12]],levelup:[[392,.1],[523,.1],[659,.1],[784,.18]],complete:[[523,.08],[659,.08],[784,.08],[1047,.22]]
  };
  const notes=sets[type]||sets.click,now=audioCtx.currentTime;
  notes.forEach((n,i)=>{const o=audioCtx.createOscillator(),g=audioCtx.createGain();o.type=type==='wrong'?'triangle':'sine';o.frequency.value=n[0];g.gain.setValueAtTime(.0001,now+i*.09);g.gain.exponentialRampToValueAtTime(.075,now+i*.09+.015);g.gain.exponentialRampToValueAtTime(.0001,now+i*.09+n[1]);o.connect(g);g.connect(audioCtx.destination);o.start(now+i*.09);o.stop(now+i*.09+n[1]+.03)})
 }catch(e){}
}
function makeParticles(){const box=$('particles');if(!box)return;box.innerHTML='';for(let i=0;i<55;i++){const p=document.createElement('i');p.className='particle';const size=2+Math.random()*5;p.style.width=p.style.height=`${size}px`;p.style.left=`${Math.random()*100}%`;p.style.animationDuration=`${9+Math.random()*18}s`;p.style.animationDelay=`-${Math.random()*22}s`;box.appendChild(p)}}
function celebrate(){const box=document.createElement('div');box.className='celebration';for(let i=0;i<42;i++){const s=document.createElement('i');s.textContent=['✦','★','●','◆'][i%4];s.style.setProperty('--x',`${Math.random()*100}vw`);s.style.setProperty('--r',`${Math.random()*360}deg`);s.style.setProperty('--d',`${Math.random()*.7}s`);box.appendChild(s)}document.body.appendChild(box);setTimeout(()=>box.remove(),1800)}

/* ---------- BANCO EDUCACIONAL ----------
   Cada registro gera 10 perguntas distintas. 25 registros × 10 = 250 perguntas/matéria.
   O sistema usa todas as 250 antes de permitir novo ciclo.
*/
function makeQuestion(id,text,correct,wrong,topic){return{id,text,correct,answers:unique([correct,...wrong]),topic}}
const variants=[
 (b)=>makeQuestion(`${b.id}-a`,b.q,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-b`,`Durante uma revisão escolar, qual alternativa responde corretamente: ${b.q.toLowerCase()}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-c`,`Imagine que você precise explicar o tema “${b.t}” para um colega. Qual resposta está correta? ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-d`,`Marque a opção correta para a situação: ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-e`,`Em um quiz de ${b.t}, você encontrou a pergunta: ${b.q} Qual opção escolher?`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-f`,`Pensando no conteúdo de ${b.t}, qual alternativa completa corretamente esta ideia? ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-g`,`Qual resposta demonstra que você entendeu ${b.t}? ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-h`,`Hora do desafio! Sem consultar nada: ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-i`,`Escolha a resposta que um bom explorador do conhecimento daria: ${b.q}`,b.a,b.w,b.t),
 (b)=>makeQuestion(`${b.id}-j`,`Última forma de revisar este conceito: ${b.q}`,b.a,b.w,b.t)
];

const fact={
portugues:[
['Classes de palavras','Qual palavra é um substantivo em “O cachorro correu”?','cachorro',['correu','o','rápido']],
['Adjetivo','Em “casa bonita”, qual palavra caracteriza a casa?','bonita',['casa','em','uma']],
['Verbo','Qual palavra indica uma ação em “Ana estudou”?','estudou',['Ana','uma','livro']],
['Sinônimo','Qual palavra tem sentido semelhante a “feliz”?','contente',['distante','escuro','baixo']],
['Antônimo','Qual é o antônimo de “alto”?','baixo',['grande','largo','forte']],
['Pontuação','Qual sinal normalmente encerra uma frase afirmativa?','ponto final',['vírgula','dois-pontos','hífen']],
['Interrogação','Qual sinal aparece no final de uma pergunta direta?','ponto de interrogação',['ponto final','vírgula','ponto e vírgula']],
['Exclamação','Qual sinal pode indicar surpresa ou entusiasmo?','ponto de exclamação',['vírgula','ponto final','parêntese']],
['Acentuação','Qual palavra está escrita corretamente?','lápis',['lapis','lápiz','lápiss']],
['Plural','Qual é o plural de “flor”?','flores',['flors','florês','flor']],
['Gênero','Qual é o feminino de “ator”?','atriz',['atora','atrizta','atores']],
['Coletivo','Qual palavra representa um conjunto de peixes?','cardume',['alcateia','rebanho','enxame']],
['Pronome','Qual palavra pode substituir “Maria” em “Maria estudou”?','ela',['eles','nós','me']],
['Preposição','Qual palavra liga termos em “livro de matemática”?','de',['livro','matemática','e']],
['Conjunção','Qual palavra liga ideias em “Estudei e fiz a atividade”?','e',['estudei','fiz','atividade']],
['Sujeito','Em “Os alunos estudaram”, quem pratica a ação?','Os alunos',['estudaram','a ação','nenhum']],
['Predicado','Em “O pássaro voou”, qual é o predicado?','voou',['O pássaro','pássaro','O']],
['Frase','Qual conjunto forma uma frase com sentido completo?','O sol apareceu.',['Sol apareceu o','apareceu sol o','sol o']],
['Parágrafo','Para que serve um parágrafo?','organizar ideias relacionadas',['misturar todas as ideias','substituir letras','indicar apenas números']],
['Leitura','Ao ler um texto, identificar a ideia principal ajuda a entender:','o assunto central',['somente a primeira letra','apenas o título','o tamanho da página']],
['Ortografia','Qual forma está correta?','exceção',['excessão','eseção','ecessão']],
['Homônimos','“Manga” pode ser fruta ou parte de roupa. Isso mostra que a palavra pode ter:','mais de um sentido',['somente um som','apenas plural','nenhum significado']],
['Figuras de linguagem','“O vento sussurrava” atribui uma ação humana ao vento. Isso é:','personificação',['rima','sinestesia','onomatopeia']],
['Rima','Palavras que terminam com sons semelhantes apresentam:','rima',['parágrafo','sujeito','acentuação']],
['Texto narrativo','Qual elemento costuma apresentar os acontecimentos de uma história?','enredo',['índice','legenda de mapa','tabela periódica']]
],
ciencias:[
['Fotossíntese','Qual processo permite às plantas produzir alimento usando luz?','fotossíntese',['digestão','respiração pulmonar','evaporação']],
['Célula','Qual é a unidade básica dos seres vivos?','célula',['átomo de ferro','planeta','tecido escolar']],
['Sistema solar','Qual estrela está no centro do Sistema Solar?','Sol',['Lua','Terra','Marte']],
['Gravidade','O que mantém os objetos atraídos em direção à Terra?','gravidade',['luz','som','eletricidade estática']],
['Estados da matéria','Gelo é água em qual estado?','sólido',['líquido','gasoso','plasma']],
['Evaporação','Quando a água líquida passa para o estado gasoso, ocorre:','evaporação',['fusão','solidificação','condensação']],
['Condensação','Quando o vapor de água esfria e forma gotículas, ocorre:','condensação',['evaporação','fusão','combustão']],
['Cadeia alimentar','Em uma cadeia alimentar, as plantas geralmente são:','produtoras',['decompositoras','consumidoras terciárias','predadoras']],
['Ecossistema','Um ecossistema reúne seres vivos e:','elementos não vivos do ambiente',['somente animais','somente água','somente plantas']],
['Órgão','Qual órgão bombeia o sangue pelo corpo?','coração',['pulmão','estômago','rim']],
['Respiração','Qual gás o corpo humano utiliza na respiração?','oxigênio',['hélio','nitrogênio puro','hidrogênio']],
['Digestão','Qual órgão recebe o alimento depois do esôfago?','estômago',['coração','pulmão','cérebro']],
['Esqueleto','Qual é uma função importante do esqueleto?','sustentar e proteger o corpo',['produzir luz','bombear ar','digerir alimentos']],
['Micro-organismos','Bactérias são exemplos de:','micro-organismos',['planetas','minerais','constelações']],
['Vacinas','As vacinas ajudam o sistema imunológico a:','reconhecer e se defender de agentes específicos',['quebrar ossos','aumentar a gravidade','substituir o sangue']],
['Ciclo da água','A água que cai das nuvens em forma de chuva é chamada de:','precipitação',['fotossíntese','combustão','erosão']],
['Rochas','Rochas são formadas por combinações de:','minerais',['células nervosas','nuvens','sons']],
['Planetas','Qual planeta é conhecido por seus anéis bem visíveis?','Saturno',['Mercúrio','Vênus','Terra']],
['Lua','A Lua é o quê em relação à Terra?','satélite natural',['estrela','planeta gigante','cometa artificial']],
['Energia','Energia do Sol é uma fonte de energia:','solar',['sonora','química artificial','mecânica escolar']],
['Magnetismo','Um ímã atrai fortemente materiais como:','ferro',['papel','vidro comum','madeira']],
['Som','O som precisa de um meio material para se:','propagar',['transformar em luz','virar matéria','parar o tempo']],
['Temperatura','Qual instrumento mede a temperatura?','termômetro',['barômetro','bússola','régua']],
['Animais','Mamíferos alimentam seus filhotes principalmente com:','leite',['néctar sempre','areia','pedras']],
['Biodiversidade','A variedade de seres vivos em uma região é chamada de:','biodiversidade',['gravidade','densidade','velocidade']]
],
historia:[
['Antiguidade','Qual civilização construiu grandes pirâmides no Egito?','egípcia',['romana','viking','inca']],
['Grécia antiga','A democracia teve uma experiência importante na antiga:','Atenas',['Roma','Cartago','Esparta medieval']],
['Roma','Qual cidade foi o centro da antiga civilização romana?','Roma',['Paris','Londres','Lisboa']],
['Idade Média','O sistema social e econômico marcado por feudos foi o:','feudalismo',['capitalismo industrial','fordismo','socialismo soviético']],
['Renascimento','O Renascimento valorizou fortemente as artes e os estudos da:','Antiguidade clássica',['Idade da Pedra','Era digital','Pré-história recente']],
['Imprensa','Quem é tradicionalmente associado à popularização da imprensa de tipos móveis na Europa?','Johannes Gutenberg',['Isaac Newton','Galileu Galilei','Marco Polo']],
['Grandes navegações','As grandes navegações europeias ocorreram principalmente entre os séculos:','XV e XVI',['V e VI','IX e X','XX e XXI']],
['Brasil','Quem chegou à região que hoje corresponde ao Brasil em 1500, segundo a historiografia tradicional?','Pedro Álvares Cabral',['Dom Pedro II','Tiradentes','Getúlio Vargas']],
['Colonização','Durante a colonização portuguesa, a produção de açúcar teve grande importância no:','Brasil',['Japão','Canadá','Egito']],
['Escravidão','A escravidão no Brasil foi oficialmente abolida pela:','Lei Áurea',['Constituição de 1824','Lei de Terras','Carta Régia de 1500']],
['Independência','Em que ano ocorreu a Independência do Brasil?','1822',['1500','1889','1930']],
['Império','Quem foi o primeiro imperador do Brasil?','Dom Pedro I',['Dom Pedro II','Getúlio Vargas','Juscelino Kubitschek']],
['República','A Proclamação da República no Brasil ocorreu em:','1889',['1822','1500','1964']],
['Abolição','Em que ano foi assinada a Lei Áurea?','1888',['1822','1889','1932']],
['Revolução Industrial','A Revolução Industrial começou primeiro na:','Inglaterra',['Austrália','Argentina','China']],
['Iluminismo','O Iluminismo valorizava fortemente:','razão e pensamento crítico',['censura científica','isolamento comercial','tradição sem questionamento']],
['Revolução Francesa','A Revolução Francesa começou em:','1789',['1492','1822','1914']],
['Primeira Guerra','A Primeira Guerra Mundial começou em:','1914',['1815','1939','1945']],
['Segunda Guerra','A Segunda Guerra Mundial terminou em:','1945',['1918','1939','1955']],
['ONU','A Organização das Nações Unidas foi criada em:','1945',['1889','1914','1960']],
['Direitos humanos','A Declaração Universal dos Direitos Humanos foi adotada em:','1948',['1822','1888','2001']],
['Ditadura brasileira','O período de ditadura militar no Brasil começou em:','1964',['1930','1945','1988']],
['Redemocratização','A Constituição brasileira atualmente vigente foi promulgada em:','1988',['1964','1977','2002']],
['Tiradentes','Tiradentes ficou associado historicamente à:','Inconfidência Mineira',['Revolução Industrial','Guerra do Paraguai','Semana de Arte Moderna']],
['Patrimônio','Prédios, documentos e objetos preservados por seu valor histórico são exemplos de:','patrimônio histórico',['previsão meteorológica','recurso mineral','moeda corrente']]
],
geografia:[
['Continentes','Em qual continente fica o Brasil?','América do Sul',['Europa','Ásia','Oceania']],
['Oceanos','Qual é o maior oceano do planeta?','Pacífico',['Atlântico','Índico','Ártico']],
['Equador','A Linha do Equador divide a Terra em hemisférios:','Norte e Sul',['Leste e Oeste','Oriental e Ocidental','Ártico e Antártico']],
['Meridiano','O Meridiano de Greenwich é usado como referência para:','longitudes',['altitudes','temperaturas','chuvas']],
['Latitude','Latitude mede a distância em relação ao:','Equador',['Meridiano de Greenwich','Polo Norte somente','centro da Lua']],
['Longitude','Longitude é medida em relação ao:','Meridiano de Greenwich',['Equador','Trópico de Capricórnio','Polo Sul']],
['Relevo','Montanhas, planaltos e planícies são formas de:','relevo',['clima','vegetação','hidrografia']],
['Clima','Clima descreve padrões atmosféricos observados ao longo de:','longos períodos',['alguns segundos','uma única fotografia','uma única hora']],
['Tempo','Tempo atmosférico descreve as condições da atmosfera em:','determinado momento ou período curto',['milhares de anos apenas','interior da Terra','fases da Lua']],
['Vegetação','Florestas, campos e savanas são exemplos de:','formações vegetais',['minerais','relevos artificiais','fusos horários']],
['Amazônia','A maior parte da Floresta Amazônica está localizada na:','América do Sul',['Europa','Antártida','Oceania']],
['Rio Amazonas','O rio Amazonas está associado principalmente à bacia:','Amazônica',['do Nilo','do Mississippi','do Danúbio']],
['Urbanização','O crescimento da população vivendo em cidades é chamado de:','urbanização',['erosão','desertificação','sedimentação']],
['População','O número de habitantes de um lugar corresponde à sua:','população absoluta',['densidade vegetal','altitude','latitude']],
['Densidade demográfica','Habitantes por área ajudam a calcular a:','densidade demográfica',['temperatura média','longitude','precipitação']],
['Migração','Mudança de pessoas de um lugar para outro é chamada de:','migração',['rotação','translação','erosão']],
['Cartografia','A ciência e técnica de produzir mapas é chamada de:','cartografia',['meteorologia','biologia','arqueologia']],
['Escala','Em um mapa, a escala relaciona a distância no mapa com a distância:','real',['do tempo','do clima','da população']],
['Pontos cardeais','Quais são os quatro pontos cardeais?','norte, sul, leste e oeste',['norte, centro, cima e baixo','frio, quente, seco e úmido','mar, rio, lago e oceano']],
['Fusos horários','Os fusos horários existem porque a Terra realiza:','rotação',['somente translação','erosão','fotossíntese']],
['Globalização','A intensificação das conexões econômicas e culturais entre lugares é chamada de:','globalização',['isolamento','desmatamento','sedimentação']],
['Recursos naturais','Água, solo e minérios são exemplos de:','recursos naturais',['meios de transporte','monumentos','continentes']],
['Desmatamento','A retirada extensa da cobertura florestal é chamada de:','desmatamento',['reflorestamento','urbanização planejada','irrigação']],
['Sustentabilidade','Usar recursos pensando também nas necessidades das futuras gerações é uma ideia ligada à:','sustentabilidade',['erosão','migração','cartografia']],
['Energia renovável','Sol e vento são fontes de energia consideradas:','renováveis',['fósseis','não naturais','exauridas por definição']]
],
ingles:[
['Greetings','Qual expressão significa “bom dia” em inglês?','Good morning',['Good night','Goodbye','Thank you']],
['Thanks','Como dizer “obrigado(a)” em inglês?','Thank you',['Excuse me','See you','Good morning']],
['Colors','Qual é a tradução de “azul”?','blue',['green','yellow','brown']],
['Numbers','Qual número é “twelve”?','12',['2','20','22']],
['Family','“Mother” significa:','mãe',['irmã','tia','filha']],
['Animals','“Dog” significa:','cachorro',['gato','cavalo','pássaro']],
['School','“Teacher” significa:','professor(a)',['aluno(a)','diretor(a) de banco','médico(a)']],
['Food','“Apple” significa:','maçã',['laranja','pão','arroz']],
['Days','Qual palavra significa “segunda-feira”?','Monday',['Sunday','Friday','Saturday']],
['Months','Qual mês corresponde a “January”?','janeiro',['junho','julho','dezembro']],
['Verb to be','Qual forma completa “I ___ a student”?','am',['is','are','be']],
['Pronouns','Qual pronome significa “nós”?','we',['they','he','it']],
['Possessive','“My” significa:','meu/minha',['seu/sua','nosso/nossa','deles/delas']],
['Questions','Qual palavra costuma iniciar perguntas sobre lugares?','where',['when','who','why']],
['Questions','Qual palavra pergunta “quem”?','who',['what','where','how']],
['Adjectives','“Big” significa:','grande',['pequeno','rápido','novo']],
['Opposites','O oposto de “hot” é:','cold',['fast','tall','clean']],
['Actions','“Run” significa:','correr',['dormir','ler','cozinhar']],
['Present','Qual frase está correta?','She plays soccer.',['She play soccer.','She playing soccer.','She are plays soccer.']],
['Past','“Yesterday” indica geralmente:','ontem',['amanhã','agora','sempre']],
['Places','“Library” significa:','biblioteca',['livraria somente','laboratório','aeroporto']],
['Objects','“Chair” significa:','cadeira',['mesa','janela','porta']],
['Weather','“Rainy” significa:','chuvoso',['ensolarado','nublado somente','ventoso']],
['Feelings','“Happy” significa:','feliz',['triste','cansado','bravo']],
['Useful phrase','Qual expressão significa “por favor”?','please',['sorry','hello','welcome']]
],
informatica:[
['Hardware','Qual parte do computador executa instruções e cálculos?','processador',['monitor','mouse','alto-falante']],
['RAM','A memória RAM é usada principalmente para:','armazenar temporariamente dados em uso',['guardar arquivos para sempre','imprimir documentos','resfriar o processador']],
['SSD','Um SSD é usado principalmente para:','armazenar dados',['mostrar imagens','captar áudio','digitar texto']],
['Sistema operacional','Windows, Linux e macOS são exemplos de:','sistemas operacionais',['navegadores','linguagens de marcação','antivírus físicos']],
['Navegador','Chrome, Firefox e Edge são:','navegadores web',['sistemas de arquivos','processadores','placas de vídeo']],
['URL','O que uma URL identifica na web?','um endereço de recurso',['uma senha física','um processador','uma impressora']],
['HTML','Qual tecnologia estrutura o conteúdo de uma página web?','HTML',['CSS','SQL','PNG']],
['CSS','Qual tecnologia é usada principalmente para estilizar páginas web?','CSS',['HTML','MP3','CSV']],
['JavaScript','Qual linguagem é muito usada para adicionar interatividade a páginas web?','JavaScript',['JPEG','PDF','BIOS']],
['Backup','Criar uma cópia de segurança dos dados é fazer um:','backup',['formatador','download de tela','login']],
['Senha','Qual prática ajuda a criar uma senha mais segura?','combinar caracteres e evitar dados óbvios',['usar 123456','usar o próprio nome','repetir a mesma palavra']],
['Phishing','Uma mensagem falsa tentando roubar dados por engano é um exemplo de:','phishing',['backup','streaming','compressão']],
['Wi-Fi','Wi-Fi é uma tecnologia usada para:','conectar dispositivos sem fio',['aumentar a memória RAM','imprimir sem tinta','formatar discos']],
['Internet','A internet é melhor descrita como:','uma rede mundial de redes conectadas',['um único computador','um programa de desenho','uma memória RAM']],
['Arquivo','Um documento salvo no computador é geralmente chamado de:','arquivo',['pixel','processador','cabo']],
['Pasta','Uma pasta serve para:','organizar arquivos',['aumentar a velocidade da internet','substituir a CPU','produzir energia']],
['Pixel','A menor unidade de uma imagem digital é chamada de:','pixel',['byte de som','pasta','tecla']],
['Byte','Um byte normalmente corresponde a:','8 bits',['2 bits','16 megabytes','1 terabyte']],
['Algoritmo','Uma sequência organizada de passos para resolver um problema é um:','algoritmo',['monitor','arquivo','pixel']],
['Bug','Um erro inesperado em um programa é chamado de:','bug',['backup','browser','byte']],
['Debug','Encontrar e corrigir erros de um programa é fazer:','debug',['download','streaming','upload']],
['Variável','Em programação, uma variável pode:','guardar um valor que pode mudar',['resfriar a CPU','substituir a internet','imprimir papel']],
['Loop','Um loop em programação serve para:','repetir instruções',['apagar a tela fisicamente','aumentar a memória','criar energia']],
['Condicional','Uma estrutura “se... então” serve para:','tomar decisões com base em uma condição',['armazenar fotos','aumentar o volume','desligar o monitor']],
['Código','As instruções escritas por um programador formam o:','código-fonte',['gabinete','mousepad','cabo de rede']]
],
artes:[
['Cores primárias','No modelo tradicional de pintura, quais são três cores primárias?','vermelho, amarelo e azul',['verde, roxo e laranja','preto, branco e cinza','rosa, marrom e bege']],
['Perspectiva','Que recurso artístico cria sensação de profundidade em uma imagem?','perspectiva',['rima','ritmo musical','pontuação']],
['Escultura','A escultura trabalha principalmente com formas em:','três dimensões',['uma dimensão','somente texto','somente áudio']],
['Pintura','Qual linguagem artística usa pigmentos aplicados sobre uma superfície?','pintura',['escultura sonora','cartografia','programação']],
['Música','Qual elemento organiza a duração dos sons e silêncios?','ritmo',['perspectiva','pigmentação','parágrafo']],
['Dança','A dança utiliza principalmente movimentos do:','corpo',['papel','computador','pincel']],
['Teatro','Qual elemento é central para representar personagens em uma peça?','atuação',['cartografia','cálculo','programação']],
['Fotografia','Qual recurso da câmera controla a quantidade de luz que entra pela lente?','abertura',['paleta','argila','rima']],
['Arquitetura','A arquitetura está relacionada principalmente ao projeto de:','espaços e construções',['sons e melodias','poemas','experimentos químicos']],
['Arte abstrata','A arte abstrata pode priorizar formas, cores e linhas sem representar objetos de modo realista. Isso é:','verdadeiro',['falso','impossível','apenas música']],
['Desenho','Qual material é muito usado para fazer esboços?','lápis',['tijolo','microfone','termômetro']],
['Colagem','A colagem é criada combinando e fixando:','materiais ou imagens em uma superfície',['somente sons','apenas água','somente argila líquida']],
['Argila','A argila pode ser modelada para criar:','esculturas',['mapas meteorológicos','músicas digitais','códigos']],
['Círculo cromático','O círculo cromático ajuda a estudar:','relações entre cores',['tipos de argila','ritmos cardíacos','fusos horários']],
['Cores complementares','Cores complementares são aquelas que ficam em posições opostas no:','círculo cromático',['texto narrativo','teclado','calendário']],
['Textura','A textura em uma obra pode representar a sensação de uma superfície, como:','áspera ou lisa',['norte ou sul','alto ou baixo somente','ontem ou amanhã']],
['Linha','Linha, forma e cor são exemplos de:','elementos visuais',['sistemas operacionais','órgãos','continentes']],
['Forma','Um círculo, um quadrado e um triângulo são exemplos de:','formas geométricas',['sons','texturas musicais','movimentos migratórios']],
['Museu','Um museu de arte costuma preservar e apresentar:','obras e objetos culturais',['somente alimentos','apenas computadores','somente roupas escolares']],
['Patrimônio cultural','Festas, músicas e saberes tradicionais podem fazer parte do:','patrimônio cultural',['sistema solar','relevo','código-fonte']],
['Artista','A pessoa que cria uma obra artística pode ser chamada de:','artista',['meteorologista','programador de rede','cartógrafo apenas']],
['Criatividade','Criatividade está relacionada à capacidade de:','imaginar e criar novas possibilidades',['memorizar tudo sem compreender','medir temperatura','calcular latitude']],
['Fotografia','Uma fotografia registra uma imagem usando:','luz',['gravidade apenas','som apenas','magnetismo apenas']],
['Cinema','O cinema combina imagens em sequência para criar sensação de:','movimento',['temperatura','latitude','densidade']],
['Design','Design envolve planejar soluções considerando aspectos como função e:','forma',['gravidade','clima','longitude']]
]
};

function normalizeBase(rows,subject){return rows.map((r,i)=>({id:`${subject}-${i+1}`,t:r[0],q:r[1],a:r[2],w:r[3]}))}

/* Matemática: gerador com problemas variados e números que mudam por nível. */
function mathPool(){
 const out=[], used=new Set();
 const add=(id,text,correct,wrong,topic)=>{if(used.has(text))return;used.add(text);out.push(makeQuestion(id,text,String(correct),wrong.map(String),topic))};
 for(let l=1;l<=50;l++){
  const a=l*3+4,b=l*2+7,c=l+5;
  add(`mat-${l}-1`,`Uma biblioteca recebeu ${a} livros e depois recebeu mais ${b}. Quantos livros chegaram ao todo?`,a+b,[a+b+2,a+b-3,a+b+5],'Adição');
  add(`mat-${l}-2`,`Uma caixa tinha ${a+b} lápis e ${c} foram usados. Quantos lápis sobraram?`,a+b-c,[a+b-c+2,a+b-c-2,a+b-c+5],'Subtração');
  add(`mat-${l}-3`,`Uma professora organizou ${c} grupos com ${l%8+2} alunos em cada. Quantos alunos há nesses grupos?`,c*(l%8+2),[c*(l%8+2)+1,c*(l%8+2)-2,c*(l%8+2)+5],'Multiplicação');
  const divisor=l%7+2,total=divisor*(l%9+3);
  add(`mat-${l}-4`,`Há ${total} figurinhas para dividir igualmente entre ${divisor} crianças. Quantas cada criança recebe?`,total/divisor,[total/divisor+1,total/divisor+2,Math.max(1,total/divisor-1)],'Divisão');
  const pct=(l%5+1)*10,base=l*20+100;
  add(`mat-${l}-5`,`Uma mochila custa R$ ${base}. Qual é ${pct}% desse valor?`,`R$ ${(base*pct/100).toFixed(2).replace('.',',')}`,[`R$ ${(base*(pct+5)/100).toFixed(2).replace('.',',')}`,`R$ ${(base*(pct-5)/100).toFixed(2).replace('.',',')}`,`R$ ${(base*pct/50).toFixed(2).replace('.',',')}`],'Porcentagem');
 }
 return out;
}
function factualPool(subject){
 const bases=normalizeBase(fact[subject]||[],subject),out=[];
 bases.forEach((b)=>variants.forEach(v=>out.push(v(b))));
 return out;
}
const POOLS={matematica:mathPool()};
Object.keys(SUBJECTS).filter(s=>s!=='matematica').forEach(s=>POOLS[s]=factualPool(s));
Object.keys(POOLS).forEach(s=>{if(POOLS[s].length<250)console.warn('Banco menor que 250:',s,POOLS[s].length)});

function getUsed(subject){const p=getProgress();return Array.isArray(p.usedQuestions?.[subject])?p.usedQuestions[subject]:[]}
function saveUsed(subject,ids){const p=getProgress();p.usedQuestions[subject]=ids;saveProgress(p)}
function getLevelQuestions(subject,level){
 const pool=POOLS[subject],used=new Set(getUsed(subject));
 let available=pool.filter(q=>!used.has(q.id));
 if(available.length<QUESTIONS_PER_LEVEL){
   /* Nunca reseta antes de consumir o banco completo. */
   if(used.size>=pool.length){available=pool;saveUsed(subject,[])}
   else available=pool.filter(q=>!used.has(q.id));
 }
 const selected=shuffle(available).slice(0,QUESTIONS_PER_LEVEL);
 const after=new Set(getUsed(subject));selected.forEach(q=>after.add(q.id));saveUsed(subject,[...after]);
 return selected;
}

function completed(subject,level){return !!getProgress().completedLevels?.[`${subject}-${level}`]}
function renderSubjects(){
 const p=getProgress();updateAvatarFrame();$('playerName').textContent=currentUser;$('playerLevel').textContent=p.playerLevel;$('xpValue').textContent=p.xp;$('completedValue').textContent=Object.values(p.completedLevels||{}).filter(Boolean).length;
 const xpInLevel=p.xp%100;$('xpBar').style.width=`${xpInLevel}%`;
 const box=$('subjectsContainer');box.innerHTML='';
 Object.entries(SUBJECTS).forEach(([id,s])=>{
  const done=Array.from({length:TOTAL_LEVELS},(_,i)=>i+1).filter(l=>completed(id,l)).length;
  const card=document.createElement('article');card.className='subject-card glass';card.tabIndex=0;
  card.innerHTML=`<div class="subject-icon">${s.icon}</div><h3>${s.name}</h3><p>${s.desc}</p><div class="subject-footer"><strong>${done}/${TOTAL_LEVELS} níveis</strong><span class="play-mini">JOGAR →</span></div><div class="mini-bar"><i style="width:${done/TOTAL_LEVELS*100}%"></i></div><button class="subject-ai-btn" type="button">🤖 Professor IA</button>`;
  card.onclick=(e)=>{if(e.target.closest('.subject-ai-btn'))return;openSubject(id)};card.onkeydown=e=>{if(e.key==='Enter')openSubject(id)};card.querySelector('.subject-ai-btn').onclick=(e)=>{e.stopPropagation();openProfessor(id)};box.appendChild(card);
 });
}
function openSubject(id){currentSubject=id;const s=SUBJECTS[id];$('levelIcon').textContent=s.icon;$('levelSubjectName').textContent=s.name;$('levelsTitle').textContent=`${s.desc} • 50 níveis`;renderLevels();showScreen('levelsScreen');sound('click')}
function renderLevels(){
 const p=getProgress(),box=$('levelsContainer');box.innerHTML='';box.insertAdjacentHTML('beforeend',`<div class="subject-ai-banner" style="grid-column:1/-1"><p>🤖 <strong>Professor IA:</strong> diga o conteúdo que você quer estudar e crie uma trilha com 25 fases e 125 perguntas.</p><button type="button" class="primary-btn" id="subjectCreateAiBtn">Criar com IA</button></div>`);$('subjectCreateAiBtn').onclick=()=>openProfessor(currentSubject);let done=0;
 for(let l=1;l<=TOTAL_LEVELS;l++)if(completed(currentSubject,l))done++;
 $('subjectProgressText').textContent=`${done}/${TOTAL_LEVELS}`;$('subjectProgressBar').style.width=`${done/TOTAL_LEVELS*100}%`;
 for(let l=1;l<=TOTAL_LEVELS;l++){
  const isDone=completed(currentSubject,l),unlocked=l===1||completed(currentSubject,l-1),card=document.createElement('article');
  card.className=`level-card ${!unlocked?'locked':''} ${isDone?'completed':''} ${unlocked&&!isDone?'current':''}`;
  card.innerHTML=`<div class="level-stars">${isDone?'⭐⭐⭐':unlocked?'⭐':'🔒'}</div><div class="level-number">${l}</div><div class="level-state">${isDone?'Concluído':unlocked?'Começar missão':'Bloqueado'}</div>`;
  if(unlocked)card.onclick=()=>startLevel(l);box.appendChild(card);
 }
}
function startLevel(level){currentLevel=level;questionIndex=0;levelCorrect=0;currentQuestions=getLevelQuestions(currentSubject,level);$('gameSubject').textContent=`${SUBJECTS[currentSubject].icon} ${SUBJECTS[currentSubject].name}`;$('levelLabel').textContent=`Nível ${level}`;updateGameXp();showScreen('gameScreen');showQuestion();sound('click')}
function updateGameXp(){$('gameXp').textContent=getProgress().xp}
function showQuestion(){
 const qu=currentQuestions[questionIndex];if(!qu)return;
 $('questionNumber').textContent=`Pergunta ${questionIndex+1}/${currentQuestions.length}`;$('questionTopic').textContent=qu.topic;$('questionTag').textContent=`MISSÃO • ${qu.topic}`;$('questionText').textContent=qu.text;
 $('questionIcon').textContent=['🧠','💡','🔎','⭐','🚀'][questionIndex%5];$('questionProgressBar').style.width=`${questionIndex/currentQuestions.length*100}%`;
 $('answerMessage').textContent='';$('answerMessage').className='answer-message';
 const card=$('questionCard');card.classList.remove('enter');void card.offsetWidth;card.classList.add('enter');
 const box=$('answersContainer');box.innerHTML='';shuffle(qu.answers).forEach(answer=>{const btn=document.createElement('button');btn.className='answer-btn';btn.textContent=answer;btn.type='button';btn.onclick=()=>answerQuestion(btn,answer,qu.correct);box.appendChild(btn)})
}
function answerQuestion(btn,value,correct){
 const buttons=[...document.querySelectorAll('.answer-btn')];buttons.forEach(b=>b.disabled=true);
 if(String(value)===String(correct)){
  btn.classList.add('correct');levelCorrect++;sound('correct');$('answerMessage').textContent='🎉 Muito bem! Resposta correta!';$('answerMessage').className='answer-message good';
  const p=getProgress();const gained=8+Math.min(currentLevel,30);p.xp+=gained;saveProgress(p);updateGameXp();
  setTimeout(()=>{questionIndex++;if(questionIndex<currentQuestions.length){buttons.forEach(b=>b.remove());showQuestion()}else finishLevel()},650);
 }else{
  btn.classList.add('wrong');sound('wrong');
  const explanation=qu.explanation||`Você escolheu "${value}". A resposta correta é "${correct}".`;
  $('answerMessage').innerHTML=`❌ <strong>Você errou aqui:</strong> ${escapeHtml(explanation)}`;
  $('answerMessage').className='answer-message bad';
  setTimeout(()=>{buttons.forEach(b=>b.disabled=false);btn.disabled=true;},900);
 }
}
function finishLevel(){
 const p=getProgress(),bonus=25+currentLevel*3,old=p.playerLevel;p.xp+=bonus;p.completedLevels[`${currentSubject}-${currentLevel}`]=true;p.playerLevel=Math.max(1,Math.floor(p.xp/100)+1);saveProgress(p);updateGameXp();$('questionProgressBar').style.width='100%';$('rewardXp').textContent=bonus;$('completeText').textContent=`Você acertou as ${QUESTIONS_PER_LEVEL} perguntas e concluiu o nível ${currentLevel}!`;
 $('nextLevelBtn').textContent=currentLevel<TOTAL_LEVELS?'🚀 Próximo nível':'🏆 Finalizar matéria';$('nextLevelBtn').onclick=()=>{hideModal('completeModal');if(currentLevel<TOTAL_LEVELS)startLevel(currentLevel+1);else openSubject(currentSubject)};$('backMapBtn').onclick=()=>{hideModal('completeModal');openSubject(currentSubject)};
 celebrate();sound('complete');showModal('completeModal');if(p.playerLevel>old)setTimeout(()=>showLevelUp(p.playerLevel),700);
}
function showLevelUp(level){$('newPlayerLevel').textContent=`Nível ${level}`;showModal('levelUpModal');sound('levelup');celebrate()}
function showModal(id){$(id)?.classList.remove('hidden')}function hideModal(id){$(id)?.classList.add('hidden')}
function toast(msg){const t=$('toast');t.textContent=msg;t.classList.add('show');clearTimeout(window.__toast);window.__toast=setTimeout(()=>t.classList.remove('show'),2300)}

/* ---------- CONTROLES ---------- */
let authMode='login';
function setAuthMode(mode){
 authMode=mode;
 $('loginTab').classList.toggle('active',mode==='login');$('registerTab').classList.toggle('active',mode==='register');
 $('registerOnlyFields').classList.toggle('hidden-auth',mode!=='register');
 $('authSubmit').innerHTML=mode==='register'?'<span>📨 Criar conta e enviar código</span>':'<span>🚀 Entrar na aventura</span>';
 $('verifyBox').classList.add('hidden-auth');$('loginMessage').textContent='';
}
$('loginTab').onclick=()=>setAuthMode('login');$('registerTab').onclick=()=>setAuthMode('register');
$('forgotPasswordBtn').onclick=()=>{$('resetEmail').value=$('email').value.trim().toLowerCase();$('resetCode').value='';$('resetPassword').value='';$('resetStatus').textContent='';showModal('resetModal');sound('click')};
$('closeResetBtn').onclick=()=>hideModal('resetModal');
$('sendResetCodeBtn').onclick=async()=>{const email=$('resetEmail').value.trim().toLowerCase();if(!email||!email.includes('@')||!email.includes('.')){$('resetStatus').textContent='⚠️ Digite um e-mail válido.';return}const b=$('sendResetCodeBtn');b.disabled=true;try{const data=await requestPasswordReset(email);$('resetStatus').textContent='📧 '+data.message;toast('Código de recuperação solicitado.')}catch(err){$('resetStatus').textContent='❌ '+err.message;sound('wrong')}finally{b.disabled=false}};
$('resetPasswordBtn').onclick=async()=>{const email=$('resetEmail').value.trim().toLowerCase(),code=$('resetCode').value.trim(),pass=$('resetPassword').value;if(!/^\d{6}$/.test(code)){$('resetStatus').textContent='⚠️ Digite o código de 6 números.';return}if(pass.length<8){$('resetStatus').textContent='⚠️ A nova senha precisa ter pelo menos 8 caracteres.';return}const b=$('resetPasswordBtn');b.disabled=true;try{const data=await resetPasswordRemote(email,code,pass);currentUser=data.username;currentKey=await deriveKey(pass,data.salt);currentProgress=DEFAULT_PROGRESS();sessionStorage.setItem('educaSession',currentUser);await syncProgressRemote();hideModal('resetModal');renderSubjects();showScreen('hubScreen');toast('✅ Senha redefinida. Sua nova conta está pronta!');sound('complete')}catch(err){$('resetStatus').textContent='❌ '+err.message;sound('wrong')}finally{b.disabled=false}};
$('loginForm').addEventListener('submit',async e=>{
 e.preventDefault();
 const email=$('email').value.trim().toLowerCase(),pass=$('password').value, name=normalizeName($('username').value);
 const submit=e.submitter;
 if(!email||!email.includes('@')||!email.includes('.')){$('loginMessage').textContent='⚠️ Digite um e-mail válido.';return}
 if(pass.length<8){$('loginMessage').textContent='⚠️ A senha precisa ter pelo menos 8 caracteres.';return}
 if(authMode==='register'&&name.length<2){$('loginMessage').textContent='⚠️ Digite um usuário com pelo menos 2 caracteres.';return}
 if(submit){submit.disabled=true;submit.dataset.oldText=submit.innerHTML;submit.innerHTML='⏳ Aguarde...'}
 try{
  if(authMode==='register'){
   await registerRemote(name,email,pass);pendingEmail=email;$('verifyBox').classList.remove('hidden-auth');$('loginMessage').textContent='📧 Código enviado! Verifique seu e-mail e digite os 6 números.';toast('Código de confirmação enviado.');return;
  }
  const data=await loginRemote(email,pass);
  currentUser=data.username;accountSalt=data.salt;currentKey=await deriveKey(pass,accountSalt);
  currentProgress=await openServerProgress(data.progress,currentKey);
  sessionStorage.setItem('educaSession',currentUser);
  renderSubjects();showScreen('hubScreen');$('loginMessage').textContent='';$('password').value='';sound('click');toast(`Bem-vindo(a), ${currentUser}! 🚀`);
 }catch(err){
  if(err.data?.error==='CONFIRM_EMAIL'){$('loginMessage').textContent='📧 Seu e-mail ainda não foi confirmado. Use o botão de criar conta para solicitar um novo código.';setAuthMode('register');pendingEmail=err.data.email;$('email').value=pendingEmail;$('verifyBox').classList.remove('hidden-auth')}
  else $('loginMessage').textContent='❌ '+err.message;
  sound('wrong');
 }finally{if(submit){submit.disabled=false;submit.innerHTML=submit.dataset.oldText||'🚀 Entrar na aventura'}}
});
$('verifyBtn').onclick=async()=>{const code=$('verifyCode').value.trim();if(!pendingEmail||!/^\d{6}$/.test(code)){$('loginMessage').textContent='⚠️ Digite o código de 6 números.';return}try{const data=await verifyRemote(pendingEmail,code);currentUser=data.username;currentKey=await deriveKey($('password').value,data.salt);currentProgress=await openServerProgress(data.progress,currentKey);sessionStorage.setItem('educaSession',currentUser);await syncProgressRemote();renderSubjects();showScreen('hubScreen');$('loginMessage').textContent='';toast('✅ E-mail confirmado! Bem-vindo(a) ao Educa-.');sound('complete')}catch(err){$('loginMessage').textContent='❌ '+err.message;sound('wrong')}};
$('resendBtn').onclick=async()=>{if(!pendingEmail)return;try{await api('/api/auth/resend',{method:'POST',body:JSON.stringify({email:pendingEmail})});toast('📧 Novo código enviado.')}catch(err){$('loginMessage').textContent='❌ '+err.message}};
$('togglePassword').onclick=()=>{$('password').type=$('password').type==='password'?'text':'password'};
$('logoutBtn').onclick=async()=>{await logoutRemote();sessionStorage.removeItem('educaSession');currentUser='';currentKey=null;currentProgress=DEFAULT_PROGRESS();$('username').value='';$('email').value='';$('password').value='';showScreen('loginScreen');sound('click')};
$('backSubjects').onclick=()=>{renderSubjects();showScreen('hubScreen');sound('click')};
$('quitGame').onclick=()=>{openSubject(currentSubject);toast('Fase pausada. Seu progresso concluído continua salvo.')};
$('closeLevelUp').onclick=()=>hideModal('levelUpModal');
$('backMapBtn').onclick=()=>{};
$('fullscreenBtn').onclick=async()=>{try{if(!document.fullscreenElement)await document.documentElement.requestFullscreen();else await document.exitFullscreen()}catch{toast('Tela cheia não foi permitida pelo navegador.')}};

(function init(){
 makeParticles();
 const loader=$('loadingScreen');
 // Abertura: foguete → explosão → nome do app → carregamento → login.
 setTimeout(()=>loader?.classList.add('done'),5000);
 /* Por segurança, a senha é exigida novamente ao abrir o site. */
 setTimeout(()=>showScreen('loginScreen'),5050);
})();

/* =========================================================
   EXPANSÃO EDUCA- — PERSONAGEM, LOJA, CONQUISTAS,
   CRIADOR DE FASES, MOEDAS E TAXA DE ACERTO
========================================================= */

const SHOP_SKINS=[
 {id:'default',name:'Aventureiro',icon:'🙂',body:'🧥',price:0},
 {id:'robot',name:'Robô',icon:'🤖',body:'🦾',price:45},
 {id:'ninja',name:'Ninja',icon:'🥷',body:'🖤',price:70},
 {id:'astronaut',name:'Astronauta',icon:'👨‍🚀',body:'🚀',price:90},
 {id:'wizard',name:'Mago',icon:'🧙',body:'🪄',price:110},
 {id:'detective',name:'Detetive',icon:'🕵️',body:'🧥',price:125},
 {id:'artist',name:'Artista',icon:'👩‍🎨',body:'🎨',price:140},
 {id:'scientist',name:'Cientista',icon:'🧑‍🔬',body:'🥼',price:160}
];
const SHOP_ITEMS=[
 {id:'star',name:'Estrela',icon:'⭐',price:25},
 {id:'crown',name:'Coroa',icon:'👑',price:55},
 {id:'glasses',name:'Óculos',icon:'🤓',price:40},
 {id:'rocket',name:'Foguete',icon:'🚀',price:65},
 {id:'book',name:'Livro',icon:'📚',price:35},
 {id:'fire',name:'Chamas',icon:'🔥',price:80},
 {id:'diamond',name:'Diamante',icon:'💎',price:100},
 {id:'medal',name:'Medalha',icon:'🏅',price:75}
];
const ACHIEVEMENTS=[
 {id:'first',icon:'🌟',name:'Primeira missão',desc:'Conclua sua primeira fase.',reward:40,frame:'bronze',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=1},
 {id:'five',icon:'🔥',name:'Aquecendo',desc:'Conclua 5 fases.',reward:60,frame:'flame',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=5},
 {id:'ten',icon:'🚀',name:'Explorador',desc:'Conclua 10 fases.',reward:80,frame:'rocket',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=10},
 {id:'twentyfive',icon:'🏆',name:'Craque do estudo',desc:'Conclua 25 fases.',reward:120,frame:'gold',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=25},
 {id:'fifty',icon:'💎',name:'Colecionador de conhecimento',desc:'Conclua 50 fases.',reward:160,frame:'diamond',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=50},
 {id:'hundred',icon:'👑',name:'Mestre Educa',desc:'Conclua 100 fases.',reward:200,frame:'royal',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=100},
 {id:'twohundred',icon:'🌌',name:'Lenda da aprendizagem',desc:'Conclua 200 fases.',reward:300,frame:'galaxy',check:p=>Object.values(p.completedLevels||{}).filter(Boolean).length>=200},
 {id:'fourhundred',icon:'🌈',name:'Universo completo',desc:'Conclua os 400 níveis principais.',reward:500,frame:'rainbow',check:p=>Object.keys(SUBJECTS).every(s=>Array.from({length:50},(_,i)=>p.completedLevels?.[`${s}-${i+1}`]).every(Boolean))},
 {id:'perfect',icon:'💯',name:'Resposta perfeita',desc:'Termine uma fase acertando todas.',reward:35,frame:'perfect',check:p=>Number(p.perfectPhases)>=1},
 {id:'perfect10',icon:'🎯',name:'Mira certeira',desc:'Consiga 10 fases perfeitas.',reward:100,frame:'target',check:p=>Number(p.perfectPhases)>=10},
 {id:'allsubjects',icon:'🌎',name:'Conhecimento total',desc:'Conclua pelo menos uma fase em todas as matérias.',reward:150,frame:'world',check:p=>Object.keys(SUBJECTS).every(s=>Object.keys(p.completedLevels||{}).some(k=>k.startsWith(s+'-')))},
 {id:'math',icon:'➗',name:'Mente matemática',desc:'Conclua 10 níveis de Matemática.',reward:70,frame:'math',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('matematica-')).length>=10},
 {id:'language',icon:'📖',name:'Guardião das palavras',desc:'Conclua 10 níveis de Português.',reward:70,frame:'book',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('portugues-')).length>=10},
 {id:'science',icon:'🔬',name:'Pequeno cientista',desc:'Conclua 10 níveis de Ciências.',reward:70,frame:'science',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('ciencias-')).length>=10},
 {id:'history',icon:'🏛️',name:'Viajante do tempo',desc:'Conclua 10 níveis de História.',reward:70,frame:'history',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('historia-')).length>=10},
 {id:'geography',icon:'🧭',name:'Explorador do planeta',desc:'Conclua 10 níveis de Geografia.',reward:70,frame:'geo',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('geografia-')).length>=10},
 {id:'english',icon:'🇺🇸',name:'English star',desc:'Conclua 10 níveis de Inglês.',reward:70,frame:'english',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('ingles-')).length>=10},
 {id:'tech',icon:'💻',name:'Mestre da tecnologia',desc:'Conclua 10 níveis de Informática.',reward:70,frame:'tech',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('informatica-')).length>=10},
 {id:'art',icon:'🎨',name:'Artista criativo',desc:'Conclua 10 níveis de Artes.',reward:70,frame:'art',check:p=>Object.keys(p.completedLevels||{}).filter(k=>k.startsWith('artes-')).length>=10},
 {id:'collector',icon:'🛍️',name:'Colecionador',desc:'Compre pelo menos 3 itens.',reward:50,frame:'shop',check:p=>Object.keys(p.ownedItems||{}).filter(k=>k!=='default').length>=3},
 {id:'ai',icon:'🤖',name:'Amigo do Professor IA',desc:'Conclua 5 fases criadas pelo Professor IA.',reward:100,frame:'ai',check:p=>Object.values(p.aiCurricula||{}).reduce((n,c)=>n+Object.values(c.completed||{}).filter(Boolean).length,0)>=5},
 {id:'streak',icon:'🔥',name:'Constância',desc:'Responda pelo menos 50 questões.',reward:80,frame:'streak',check:p=>Object.values(p.accuracy||{}).reduce((n,a)=>n+(a.total||0),0)>=50}
];

const AVATAR_FRAMES=[
 {id:'default',name:'Clássica',icon:'✦',className:'frame-default',source:null},
 {id:'bronze',name:'Bronze',icon:'🥉',className:'frame-bronze',source:'first'},
 {id:'flame',name:'Chamas',icon:'🔥',className:'frame-flame',source:'five'},
 {id:'rocket',name:'Foguete',icon:'🚀',className:'frame-rocket',source:'ten'},
 {id:'gold',name:'Ouro',icon:'🏆',className:'frame-gold',source:'twentyfive'},
 {id:'diamond',name:'Diamante',icon:'💎',className:'frame-diamond',source:'fifty'},
 {id:'royal',name:'Real',icon:'👑',className:'frame-royal',source:'hundred'},
 {id:'galaxy',name:'Galáxia',icon:'🌌',className:'frame-galaxy',source:'twohundred'},
 {id:'rainbow',name:'Arco-íris',icon:'🌈',className:'frame-rainbow',source:'fourhundred'},
 {id:'perfect',name:'Perfeição',icon:'💯',className:'frame-perfect',source:'perfect'},
 {id:'target',name:'Precisão',icon:'🎯',className:'frame-target',source:'perfect10'},
 {id:'world',name:'Mundo',icon:'🌎',className:'frame-world',source:'allsubjects'},
 {id:'math',name:'Matemática',icon:'➗',className:'frame-math',source:'math'},
 {id:'book',name:'Palavras',icon:'📖',className:'frame-book',source:'language'},
 {id:'science',name:'Ciência',icon:'🔬',className:'frame-science',source:'science'},
 {id:'history',name:'História',icon:'🏛️',className:'frame-history',source:'history'},
 {id:'geo',name:'Exploração',icon:'🧭',className:'frame-geo',source:'geography'},
 {id:'english',name:'English',icon:'🇺🇸',className:'frame-english',source:'english'},
 {id:'tech',name:'Tecnologia',icon:'💻',className:'frame-tech',source:'tech'},
 {id:'art',name:'Arte',icon:'🎨',className:'frame-art',source:'art'},
 {id:'shop',name:'Colecionador',icon:'🛍️',className:'frame-shop',source:'collector'},
 {id:'ai',name:'Professor IA',icon:'🤖',className:'frame-ai',source:'ai'},
 {id:'streak',name:'Constância',icon:'🔥',className:'frame-streak',source:'streak'}
];

function ensureProgress(p){
 p=p||{};
 p.xp=Number(p.xp)||0;
 p.playerLevel=Math.max(1,Number(p.playerLevel)||1);
 p.completedLevels=p.completedLevels||{};
 p.usedQuestions=p.usedQuestions||{};
 p.coins=Number(p.coins)||0;
 p.ownedItems=p.ownedItems||{default:true};
 p.equippedSkin=p.equippedSkin||'default';
 p.equippedItem=p.equippedItem||'';
 p.achievements=p.achievements||{};
 p.perfectPhases=Number(p.perfectPhases)||0;
 p.accuracy=p.accuracy||{};
 p.economyInitialized=!!p.economyInitialized;
 if(!p.economyInitialized){p.coins+=60;p.economyInitialized=true}
 Object.keys(SUBJECTS).forEach(s=>{if(!p.accuracy[s])p.accuracy[s]={correct:0,total:0}});
 return p;
}

const originalGetProgress=getProgress;
getProgress=function(){currentProgress=ensureProgress(currentProgress);return currentProgress};
const originalSaveProgress=saveProgress;
saveProgress=function(p){p=ensureProgress(p);return originalSaveProgress(p)};

const baseEnsureProgress=ensureProgress;
ensureProgress=function(p){
 p=baseEnsureProgress(p);p.aiCurricula=p.aiCurricula||{};p.unlockedFrames=p.unlockedFrames||{default:true};p.equippedFrame=p.equippedFrame||'default';
 AVATAR_FRAMES.forEach(f=>{if(f.source&&p.achievements?.[f.source])p.unlockedFrames[f.id]=true});
 return p;
};

function updateAvatarFrame(){
 const p=getProgress();
 const frame=AVATAR_FRAMES.find(f=>f.id===p.equippedFrame&&p.unlockedFrames[f.id])||AVATAR_FRAMES[0];
 const skin=SHOP_SKINS.find(x=>x.id===p.equippedSkin)||SHOP_SKINS[0];
 const item=SHOP_ITEMS.find(x=>x.id===p.equippedItem);
 const el=$('playerFrame');
 if(el){
  el.className=`avatar-frame ${frame.className}`;
  el.title=frame.name;
  el.innerHTML=`<span class="mini-avatar"><span class="mini-head">${escapeHtml(skin.icon)}</span><span class="mini-body">${escapeHtml(skin.body)}</span><span class="mini-item">${item?escapeHtml(item.icon):''}</span></span>`;
 }
}

function awardAchievements(){
 const p=getProgress();let gained=0;
 ACHIEVEMENTS.forEach(a=>{
  if(!p.achievements[a.id]&&a.check(p)){
   p.achievements[a.id]=true;if(a.frame)p.unlockedFrames[a.frame]=true;p.coins+=a.reward;gained+=a.reward;
   setTimeout(()=>toast(`🏆 Conquista: ${a.name}  +${a.reward} moedas`),250);
  }
 });
 if(gained)saveProgress(p);
 return gained;
}

function updateHubEconomy(){
 const p=getProgress();
 if($('coinsValue'))$('coinsValue').textContent=p.coins;
 updateCharacterPreview();
}

/* ---------- PERSONAGEM 3D INTERATIVO ---------- */
let characterRotation=0,draggingCharacter=false,lastPointerX=0;
function updateCharacterPreview(){
 const p=getProgress(),skin=SHOP_SKINS.find(x=>x.id===p.equippedSkin)||SHOP_SKINS[0],item=SHOP_ITEMS.find(x=>x.id===p.equippedItem);
 ['charHead','customHead'].forEach(id=>{if($(id))$(id).textContent=skin.icon});
 ['charBody','customBody'].forEach(id=>{if($(id))$(id).textContent=skin.body});
 ['charItem','customItem'].forEach(id=>{if($(id))$(id).textContent=item?item.icon:''});
 ['character3d'].forEach(id=>{if($(id))$(id).style.transform=`rotateY(${characterRotation}deg)`});
}
function setupCharacterDrag(){
 const stage=$('characterStage');if(!stage||stage.dataset.ready)return;stage.dataset.ready='1';
 stage.addEventListener('pointerdown',e=>{draggingCharacter=true;lastPointerX=e.clientX;stage.setPointerCapture?.(e.pointerId)});
 stage.addEventListener('pointermove',e=>{if(!draggingCharacter)return;characterRotation+=(e.clientX-lastPointerX)*.65;lastPointerX=e.clientX;updateCharacterPreview()});
 ['pointerup','pointercancel','pointerleave'].forEach(ev=>stage.addEventListener(ev,()=>draggingCharacter=false));
}
function openCharacter(){updateCharacterPreview();setupCharacterDrag();showModal('characterModal');sound('click')}

/* ---------- LOJA ---------- */
function renderShop(){
 const p=getProgress();if($('shopCoins'))$('shopCoins').textContent=`🪙 ${p.coins}`;const box=$('shopGrid');if(!box)return;box.innerHTML='';
 [...SHOP_SKINS.map(x=>({...x,type:'skin'})),...SHOP_ITEMS.map(x=>({...x,type:'item'}))].forEach(item=>{
  const owned=!!p.ownedItems[item.id]||item.price===0;const el=document.createElement('article');el.className=`shop-item ${owned?'owned':''}`;
  el.innerHTML=`<div class="item-icon">${item.icon}</div><h3>${item.name}</h3><small>${owned?'✔ Comprado':'🪙 '+item.price}</small><button type="button">${owned?'Usar':'Comprar'}</button>`;
  el.querySelector('button').onclick=()=>{if(owned){equipItem(item)}else buyItem(item)};box.appendChild(el);
 });
}
function buyItem(item){
 const p=getProgress();if(p.coins<item.price){toast('🪙 Você ainda precisa de mais moedas.');sound('wrong');return}
 p.coins-=item.price;p.ownedItems[item.id]=true;saveProgress(p);equipItem(item);awardAchievements();renderShop();updateHubEconomy();toast(`✨ ${item.name} comprado!`);sound('correct')
}
function equipItem(item){
 const p=getProgress();if(SHOP_SKINS.some(x=>x.id===item.id))p.equippedSkin=item.id;else p.equippedItem=item.id;saveProgress(p);updateCharacterPreview();renderShop();renderCustomization();toast(`🎨 ${item.name} equipado!`)
}

/* ---------- PERSONALIZAÇÃO ---------- */
function renderCustomization(){
 const p=getProgress();
 const skins=$('skinOptions'),items=$('itemOptions');if(!skins||!items)return;
 skins.innerHTML='';items.innerHTML='';
 SHOP_SKINS.forEach(item=>{if(!p.ownedItems[item.id])return;const b=document.createElement('button');b.className=`option-btn ${p.equippedSkin===item.id?'selected':''}`;b.textContent=item.icon;b.title=item.name;b.onclick=()=>{p.equippedSkin=item.id;saveProgress(p);renderCustomization();updateCharacterPreview()};skins.appendChild(b)});
 SHOP_ITEMS.forEach(item=>{if(!p.ownedItems[item.id])return;const b=document.createElement('button');b.className=`option-btn ${p.equippedItem===item.id?'selected':''}`;b.textContent=item.icon;b.title=item.name;b.onclick=()=>{p.equippedItem=item.id;saveProgress(p);renderCustomization();updateCharacterPreview()};items.appendChild(b)});
}
function openCustomization(){renderCustomization();updateCharacterPreview();showModal('customModal');sound('click')}

/* ---------- CONQUISTAS ---------- */
function renderAchievements(){
 const p=getProgress(),box=$('achievementGrid'),frames=$('frameGrid');if(!box)return;box.innerHTML='';
 ACHIEVEMENTS.forEach(a=>{const unlocked=!!p.achievements[a.id],frame=a.frame?AVATAR_FRAMES.find(f=>f.id===a.frame):null,el=document.createElement('article');el.className=`achievement ${unlocked?'unlocked':''}`;el.innerHTML=`<div class="achievement-icon">${unlocked?a.icon:'🔒'}</div><h3>${a.name}</h3><p>${a.desc}</p><small>${unlocked?'✔ Conquistada':'+'+a.reward+' 🪙'}</small>${frame?`<div class="achievement-frame-preview ${unlocked?frame.className:''}">${unlocked?frame.icon:'🔒'}</div>`:''}`;box.appendChild(el)});
 if(frames){frames.innerHTML='';AVATAR_FRAMES.forEach(f=>{const unlocked=!!p.unlockedFrames[f.id];const b=document.createElement('button');b.type='button';b.className=`frame-option ${unlocked?'unlocked':''} ${p.equippedFrame===f.id?'selected':''} ${f.className}`;b.innerHTML=`<span>${unlocked?f.icon:'🔒'}</span><small>${f.name}</small>`;b.disabled=!unlocked;b.onclick=()=>{p.equippedFrame=f.id;saveProgress(p);updateAvatarFrame();renderAchievements();toast(`🖼️ Moldura ${f.name} equipada!`)};frames.appendChild(b)})}
}
function openAchievements(){renderAchievements();showModal('achievementsModal');sound('click')}

/* ---------- PROGRESSO E TAXA DE ACERTO ---------- */
function renderAccuracy(){
 const p=getProgress(),box=$('accuracyGrid');if(!box)return;box.innerHTML='';
 Object.entries(SUBJECTS).forEach(([id,s])=>{const a=p.accuracy[id]||{correct:0,total:0},rate=a.total?Math.round(a.correct/a.total*100):0;const el=document.createElement('div');el.className='accuracy-row';el.innerHTML=`<div class="accuracy-top"><span>${s.icon} ${s.name}</span><span>${rate}%</span></div><div class="accuracy-bar"><i style="width:${rate}%"></i></div><small>${a.correct} acertos de ${a.total} respostas</small>`;box.appendChild(el)})
}
function openProgress(){renderAccuracy();showModal('progressModal');sound('click')}

/* ---------- CRIADOR DE FASE ---------- */
let phaseTopics=[];
function availableTopics(){return unique((POOLS[currentSubject]||[]).map(q=>q.topic)).slice(0,30)}
function openPhaseBuilder(level){
 currentLevel=level;phaseTopics=[];const box=$('topicChoices');box.innerHTML='';
 availableTopics().forEach(topic=>{const b=document.createElement('button');b.type='button';b.className='topic-choice';b.textContent=topic;b.onclick=()=>{if(phaseTopics.includes(topic)){phaseTopics=phaseTopics.filter(x=>x!==topic);b.classList.remove('selected')}else if(phaseTopics.length<3){phaseTopics.push(topic);b.classList.add('selected')}updateBuilderDifficulty(level)};box.appendChild(b)});
 updateBuilderDifficulty(level);showModal('phaseBuilderModal');sound('click')
}
function updateBuilderDifficulty(level){const d=level<=10?'⭐ Básica':level<=20?'⭐⭐ Intermediária':level<=30?'⭐⭐⭐ Avançada':level<=40?'⭐⭐⭐⭐ Desafiadora':'⭐⭐⭐⭐⭐ Mestre';if($('builderDifficulty'))$('builderDifficulty').textContent=`Dificuldade da fase ${level}: ${d} • escolha até 3 conteúdos`}
function generatePhase(){
 if(!phaseTopics.length){toast('📚 Escolha pelo menos um conteúdo.');sound('wrong');return}
 hideModal('phaseBuilderModal');startLevel(currentLevel,phaseTopics);sound('click')
}

/* ---------- PERGUNTAS POR CONTEÚDO E SEM REPETIÇÃO ---------- */
getLevelQuestions=function(subject,level,topics=[]){
 const pool=POOLS[subject]||[];const used=new Set(getUsed(subject));
 let candidates=pool.filter(q=>!used.has(q.id));
 if(topics.length)candidates=candidates.filter(q=>topics.includes(q.topic));
 if(candidates.length<QUESTIONS_PER_LEVEL){
  const fallback=pool.filter(q=>!used.has(q.id));
  candidates=unique([...candidates,...fallback].map(q=>q.id)).map(id=>pool.find(q=>q.id===id)).filter(Boolean);
 }
 if(candidates.length<QUESTIONS_PER_LEVEL&&used.size>=pool.length){
  toast('🏆 Todas as perguntas desta matéria já foram usadas!');
  return [];
 }
 const selected=shuffle(candidates).slice(0,QUESTIONS_PER_LEVEL);const after=new Set(used);selected.forEach(q=>after.add(q.id));saveUsed(subject,[...after]);return selected;
}

/* ---------- RENDER DOS NÍVEIS COM CRIADOR ---------- */
renderLevels=function(){
 const p=getProgress(),box=$('levelsContainer');box.innerHTML='';let done=0;for(let l=1;l<=TOTAL_LEVELS;l++)if(completed(currentSubject,l))done++;
 $('subjectProgressText').textContent=`${done}/${TOTAL_LEVELS}`;$('subjectProgressBar').style.width=`${done/TOTAL_LEVELS*100}%`;
 for(let l=1;l<=TOTAL_LEVELS;l++){
  const isDone=completed(currentSubject,l),unlocked=l===1||completed(currentSubject,l-1),card=document.createElement('article');card.className=`level-card ${!unlocked?'locked':''} ${isDone?'completed':''} ${unlocked&&!isDone?'current':''}`;
  card.innerHTML=`<div class="level-stars">${isDone?'⭐⭐⭐':unlocked?'⭐':'🔒'}</div><div class="level-number">${l}</div><div class="level-state">${isDone?'Concluído':unlocked?'Escolher conteúdo':'Bloqueado'}</div>`;
  if(unlocked)card.onclick=()=>openPhaseBuilder(l);box.appendChild(card);
 }
}

/* ---------- INÍCIO DA FASE ---------- */
startLevel=function(level,topics=[]){
 currentMissionIsAI=false;
 currentLevel=level;questionIndex=0;levelCorrect=0;currentQuestions=getLevelQuestions(currentSubject,level,topics);
 if(!currentQuestions.length){renderLevels();showScreen('levelsScreen');return}
 $('gameSubject').textContent=`${SUBJECTS[currentSubject].icon} ${SUBJECTS[currentSubject].name}`;$('levelLabel').textContent=`Nível ${level}`;updateGameXp();showScreen('gameScreen');showQuestion();sound('click')
}

/* ---------- FEEDBACK DO ERRO + ESTATÍSTICAS ---------- */
answerQuestion=function(btn,value,correct){
 const buttons=[...document.querySelectorAll('.answer-btn')];buttons.forEach(b=>b.disabled=true);const qu=currentQuestions[questionIndex],p=getProgress();
 p.accuracy[currentSubject]=p.accuracy[currentSubject]||{correct:0,total:0};p.accuracy[currentSubject].total++;
 if(String(value)===String(correct)){
  btn.classList.add('correct');levelCorrect++;p.accuracy[currentSubject].correct++;sound('correct');$('answerMessage').textContent='🎉 Muito bem! Você entendeu o conteúdo.';$('answerMessage').className='answer-message good';
  const gained=8+Math.min(currentLevel,30);p.xp+=gained;saveProgress(p);updateGameXp();setTimeout(()=>{questionIndex++;if(questionIndex<currentQuestions.length){buttons.forEach(b=>b.remove());showQuestion()}else finishLevel()},700);
 }else{
  btn.classList.add('wrong');buttons.find(b=>String(b.textContent)===String(correct))?.classList.add('correct');sound('wrong');saveProgress(p);
  const box=$('answerMessage');box.className='answer-message bad';box.innerHTML=`❌ <b>Você errou aqui:</b> ${qu.topic}.<div class="error-box"><b>Sua resposta:</b> ${String(value)}<br><b>Resposta correta:</b> ${String(correct)}<br><span>💡 Por quê? ${escapeHtml(qu.explanation||`A alternativa correta corresponde ao conceito de ${qu.topic}.`)}</span></div>`;
  setTimeout(()=>{buttons.forEach(b=>b.disabled=false);btn.disabled=true},1300);
 }
}

/* ---------- FASE COMPLETA: MOEDAS EQUILIBRADAS ---------- */
finishLevel=function(){
 const p=getProgress(),old=p.playerLevel;
 if(currentMissionIsAI){
  const bonusXp=20+levelCorrect*6,coinReward=5+levelCorrect*2;
  p.xp+=bonusXp;p.coins+=coinReward;if(levelCorrect===currentQuestions.length)p.perfectPhases++;
  p.playerLevel=Math.max(1,Math.floor(p.xp/100)+1);saveProgress(p);awardAchievements();updateHubEconomy();updateGameXp();$('questionProgressBar').style.width='100%';$('rewardXp').textContent=bonusXp;$('completeText').textContent=`Missão do Professor IA concluída: ${levelCorrect}/${currentQuestions.length} acertos. +${coinReward} moedas.`;$('nextLevelBtn').textContent='📚 Voltar às matérias';$('nextLevelBtn').onclick=()=>{hideModal('completeModal');openSubject(currentSubject)};$('backMapBtn').onclick=()=>{hideModal('completeModal');openSubject(currentSubject)};celebrate();sound('complete');showModal('completeModal');if(p.playerLevel>old)setTimeout(()=>showLevelUp(p.playerLevel),700);return;
 }
 const bonusXp=25+currentLevel*3,coinReward=Math.min(18,8+Math.ceil(currentLevel/5));
 p.xp+=bonusXp;p.coins+=coinReward;p.completedLevels[`${currentSubject}-${currentLevel}`]=true;if(levelCorrect===QUESTIONS_PER_LEVEL)p.perfectPhases++;
 p.playerLevel=Math.max(1,Math.floor(p.xp/100)+1);saveProgress(p);awardAchievements();updateHubEconomy();updateGameXp();$('questionProgressBar').style.width='100%';$('rewardXp').textContent=bonusXp;$('completeText').textContent=`Você acertou ${levelCorrect}/${QUESTIONS_PER_LEVEL}. +${coinReward} moedas pela fase.`;$('nextLevelBtn').textContent=currentLevel<TOTAL_LEVELS?'🚀 Próximo nível':'🏆 Finalizar matéria';$('nextLevelBtn').onclick=()=>{hideModal('completeModal');if(currentLevel<TOTAL_LEVELS)openPhaseBuilder(currentLevel+1);else openSubject(currentSubject)};$('backMapBtn').onclick=()=>{hideModal('completeModal');openSubject(currentSubject)};celebrate();sound('complete');showModal('completeModal');if(p.playerLevel>old)setTimeout(()=>showLevelUp(p.playerLevel),700)
}

/* ---------- HUB ATUALIZADO ---------- */
const oldRenderSubjects=renderSubjects;
renderSubjects=function(){oldRenderSubjects();ensureProgress(getProgress());updateHubEconomy();};

/* ---------- BOTÕES DOS NOVOS MENUS ---------- */
$('characterBtn').onclick=openCharacter;
$('shopBtn').onclick=()=>{renderShop();showModal('shopModal');sound('click')};
$('customBtn').onclick=openCustomization;
$('achievementsBtn').onclick=openAchievements;
$('progressBtn').onclick=openProgress;
$('generatePhaseBtn').onclick=generatePhase;
$('cancelPhaseBtn').onclick=()=>hideModal('phaseBuilderModal');
$('closeCharacterBtn').onclick=()=>hideModal('characterModal');
$('closeShopBtn').onclick=()=>hideModal('shopModal');
$('closeCustomBtn').onclick=()=>hideModal('customModal');
$('closeAchievementsBtn').onclick=()=>hideModal('achievementsModal');
$('closeProgressBtn').onclick=()=>hideModal('progressModal');

/* Reforça o estado econômico depois do login. */
const oldAuthenticateHandler=document.getElementById('loginForm');
oldAuthenticateHandler.addEventListener('submit',()=>setTimeout(()=>{ensureProgress(getProgress());updateHubEconomy()},1000));


/* ---------- PROFESSOR IA ---------- */
function openProfessor(subject=''){
  const select=$('professorSubject');
  select.innerHTML=Object.entries(SUBJECTS).map(([id,s])=>`<option value="${id}">${s.icon} ${s.name}</option>`).join('');
  if(subject&&SUBJECTS[subject])select.value=subject;
  $('professorTopic').value='';$('professorStatus').textContent='';
  $('professorTitle').textContent=`Professor IA • ${SUBJECTS[select.value]?.name||'Educa-'}`;
  showModal('professorModal');sound('click');
}
$('professorSubject').onchange=()=>{$('professorTitle').textContent=`Professor IA • ${SUBJECTS[$('professorSubject').value].name}`};
const API_BASE_URL=API_BASE||'http://127.0.0.1:5000';

function fillProfessorSubjects(){
 const ids=['professorSubject','explainSubject'];ids.forEach(id=>{const el=$(id);if(!el)return;el.innerHTML='';Object.entries(SUBJECTS).forEach(([key,s])=>{const o=document.createElement('option');o.value=key;o.textContent=`${s.icon} ${s.name}`;el.appendChild(o)})});
}
function openProfessor(subject=''){
 fillProfessorSubjects();const chosen=subject&&SUBJECTS[subject]?subject:Object.keys(SUBJECTS)[0];$('professorSubject').value=chosen;$('explainSubject').value=chosen;$('professorTopic').value='';$('explainQuestion').value='';$('professorStatus').textContent='';$('explainAnswer').classList.add('hidden-auth');showModal('professorModal');sound('click')
}
$('profExplainTab').onclick=()=>{$('profExplainTab').classList.add('active');$('profCreateTab').classList.remove('active');$('profExplainPanel').classList.remove('hidden-auth');$('profCreatePanel').classList.add('hidden-auth')};
$('profCreateTab').onclick=()=>{$('profCreateTab').classList.add('active');$('profExplainTab').classList.remove('active');$('profCreatePanel').classList.remove('hidden-auth');$('profExplainPanel').classList.add('hidden-auth')};
$('professorSubject').onchange=()=>{$('professorTitle').textContent=`Professor IA • ${SUBJECTS[$('professorSubject').value].name}`};
$('askProfessorBtn').onclick=async()=>{
 const subject=$('explainSubject').value,question=$('explainQuestion').value.trim(),btn=$('askProfessorBtn');
 if(question.length<3){$('explainAnswer').classList.remove('hidden-auth');$('explainAnswer').textContent='⚠️ Escreva uma pergunta para o professor.';return}
 btn.disabled=true;btn.textContent='🤖 Professor pensando...';$('explainAnswer').classList.remove('hidden-auth');$('explainAnswer').textContent='⏳ Preparando uma explicação...';
 try{const data=await api('/api/professor/explain',{method:'POST',body:JSON.stringify({subject:SUBJECTS[subject].name,question})});$('explainAnswer').innerHTML=escapeHtml(data.answer).replace(/\n/g,'<br>')}catch(err){$('explainAnswer').textContent='❌ '+err.message;sound('wrong')}finally{btn.disabled=false;btn.textContent='🤖 Perguntar ao professor'}
};

async function generateAiCurriculum(){
 const subject=$('professorSubject').value,topic=$('professorTopic').value.trim(),difficulty=$('professorDifficulty').value,btn=$('generateAiBtn');
 if(topic.length<3){$('professorStatus').textContent='⚠️ Digite o conteúdo que você quer estudar.';return}
 btn.disabled=true;btn.textContent='🤖 Criando 25 fases...';$('professorStatus').textContent='O professor está montando 125 perguntas diferentes. Isso pode levar um pouco mais de tempo.';
 try{
  const data=await api('/api/professor/curriculum',{method:'POST',body:JSON.stringify({subject:SUBJECTS[subject].name,topic,difficulty})});
  const p=getProgress();p.aiCurricula[subject]={subject:SUBJECTS[subject].name,topic,difficulty,phases:data.phases,completed:{}};saveProgress(p);hideModal('professorModal');openAiCurriculum(subject);toast('🤖 Trilha criada: 25 fases e 125 perguntas!');sound('levelup');
 }catch(err){$('professorStatus').textContent='❌ '+err.message;sound('wrong')}finally{btn.disabled=false;btn.textContent='🚀 Criar 25 fases'}
}
function openAiCurriculum(subject){
 const p=getProgress(),c=p.aiCurricula?.[subject];if(!c)return openProfessor(subject);currentSubject=subject;$('curriculumTitle').textContent=`${SUBJECTS[subject].icon} ${c.topic}`;$('curriculumInfo').textContent=`${c.subject} • 25 fases • 5 perguntas por fase • dificuldade ${c.difficulty}`;const box=$('curriculumGrid');box.innerHTML='';
 c.phases.forEach((phase,i)=>{const done=!!c.completed?.[String(i+1)],unlocked=i===0||!!c.completed?.[String(i)];const card=document.createElement('article');card.className=`curriculum-card ${done?'completed':''} ${!unlocked?'locked':''}`;card.innerHTML=`<div class="curriculum-number">${done?'✓':i+1}</div><div><b>${escapeHtml(phase.title)}</b><small>${escapeHtml(phase.focus)}</small><span>${done?'Concluída':unlocked?'5 perguntas':'🔒 Bloqueada'}</span></div>`;if(unlocked)card.onclick=()=>startAiPhase(subject,i+1);box.appendChild(card)})
 showModal('aiCurriculumModal');sound('click')
}
function startAiPhase(subject,phase){
 const p=getProgress(),c=p.aiCurricula?.[subject],data=c?.phases?.[phase-1];if(!data)return;
 currentSubject=subject;currentLevel=phase;currentAiCurriculum=subject;currentAiPhase=phase;currentMissionIsAI=true;questionIndex=0;levelCorrect=0;currentQuestions=data.questions.map((q,i)=>({id:`ai-${subject}-${phase}-${i}`,text:q.question,answers:q.answers,correct:q.correct,topic:q.topic||c.topic,explanation:q.explanation}));
 hideModal('aiCurriculumModal');$('gameSubject').textContent=`🤖 ${SUBJECTS[subject].name}`;$('levelLabel').textContent=`Professor IA • Fase ${phase}/25`;$('questionNumber').textContent='Pergunta 1/5';updateGameXp();showScreen('gameScreen');showQuestion();sound('click')
}
const oldFinishLevel=finishLevel;
let currentAiCurriculum='',currentAiPhase=0;
finishLevel=function(){
 if(currentMissionIsAI&&currentAiCurriculum){const p=getProgress();const c=p.aiCurricula?.[currentAiCurriculum];if(c){c.completed=c.completed||{};c.completed[String(currentAiPhase)]=true;saveProgress(p)}}
 const result=oldFinishLevel();
 setTimeout(()=>{if(currentMissionIsAI&&currentAiCurriculum){awardAchievements();if($('nextLevelBtn'))$('nextLevelBtn').onclick=()=>{hideModal('completeModal');openAiCurriculum(currentAiCurriculum)};if($('backMapBtn'))$('backMapBtn').onclick=()=>{hideModal('completeModal');openAiCurriculum(currentAiCurriculum)}}},100);
 return result;
};
$('generateAiBtn').onclick=generateAiCurriculum;
$('professorBtn').onclick=()=>openProfessor(currentSubject||'');
$('closeProfessorBtn').onclick=()=>hideModal('professorModal');
$('closeCurriculumBtn').onclick=()=>hideModal('aiCurriculumModal');
$('professorSubject').onchange=()=>{$('professorTitle').textContent=`Professor IA • ${SUBJECTS[$('professorSubject').value].name}`};

/* Atualiza a tela inicial e as molduras sempre que a conta entra. */
const _renderSubjects=renderSubjects;
renderSubjects=function(){_renderSubjects();updateAvatarFrame()};

