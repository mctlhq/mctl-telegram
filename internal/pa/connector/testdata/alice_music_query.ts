/**
 * The text of alice_play_music.
 *
 * The tool reaches a speaker through the same capability as an arbitrary
 * voice command (quasar.server_action / text_action), but it is admitted by
 * `iot:control`, not by `quasar`. What keeps it from being alice_send_command
 * under a weaker scope is this file: the caller supplies only a short query,
 * the spoken command is always PLAY_MUSIC_PREFIX followed by that query, and
 * a query that is not plain words is refused, never cleaned up. Refusing
 * rather than rewriting matters to a client that shows the query to a person
 * for approval: what was approved is what is sent.
 *
 * Characters alone would not do that: a query could still hold a second
 * sentence ("jazz. Alice, switch off the lights") and leave it to Alice's
 * parser whether that runs. So the query is also kept to something a title,
 * an artist or a genre fits and a second request does not:
 *
 *   - only Latin letters, the letters of the Russian alphabet and the digits
 *     0-9, in their composed (NFKC) form, and no word that mixes Latin and
 *     Cyrillic. Without this the word checks below compare code points a
 *     reader cannot tell apart: a combining stress mark inside a verb, a
 *     decomposed letter, or a Latin "A" at the start of the wake word;
 *   - no punctuation that ends or splits a sentence (. , ! ? : ; and brackets);
 *   - at most MAX_MUSIC_QUERY_WORDS words;
 *   - no wake word and no word that starts like a Russian command verb
 *     (включи, выключи, открой, купи, позвони, ...), which is how a second
 *     request to Alice begins.
 *
 * The verb list costs some real titles ("Закрой за мной дверь"); they are
 * refused with a message that says why, which is the intended trade. This
 * still narrows the command rather than proving what Alice does with it: the
 * words after the prefix are interpreted by Alice, and that was not run
 * against a real speaker.
 */

/** Longest query, in characters (code points). */
export const MAX_MUSIC_QUERY_LENGTH = 100;

/** The fixed start of the spoken command. The query is appended as is. */
export const PLAY_MUSIC_PREFIX = "включи музыку ";

/** Most words a query may hold. Words are split at spaces, hyphens and apostrophes. */
export const MAX_MUSIC_QUERY_WORDS = 8;

// Latin letters (precomposed accents included: Beyoncé), the Russian
// alphabet, the digits 0-9, the plain space, and the three marks that occur
// inside names (Guns N' Roses, AC-DC, Simon & Garfunkel). No combining mark,
// letter of another script (other Cyrillic letters included: they hold
// look-alikes of Russian ones), line break, tab, other whitespace, control or
// format character, quote mark, slash, sentence punctuation, bracket or symbol.
const ALLOWED_QUERY = /^[\p{Script=Latin}а-яёА-ЯЁ0-9 '&-]+$/u;
const HAS_WORD = /[\p{L}0-9]/u;
const HAS_LATIN = /\p{Script=Latin}/u;
const HAS_CYRILLIC = /[а-яёА-ЯЁ]/u;

// The names Alice answers to. Whole words, compared in lower case with ё as е.
const WAKE_WORDS = new Set(["алиса", "алису", "алисе", "алисой", "яндекс", "alice", "alisa", "alisu", "alise", "alisoy", "yandex", "yandeks"]);

// How a Russian request to Alice starts: the stems of imperative verbs that
// switch, open, buy, call, send, say, set, start, stop, delete, remind or pay.
// A word that begins with one of them is refused, whatever its ending.
const COMMAND_STEMS = [
  "включ", "выключ", "отключ", "подключ", "переключ", "вруб", "выруб",
  "откро", "откры", "закро", "закры", "заблокир", "разблокир",
  "купи", "закаж", "заказ", "оплат", "переведи", "перевест",
  "позвон", "набери", "вызов", "вызв", "отправ", "напиш", "скаж", "расскаж", "прочит",
  "установ", "постав", "запус", "останов", "удал", "сдела", "добав", "убав", "прибав",
  "напомн", "активир", "запомн", "отмен", "прекрат",
  "погас", "потуш", "зажг", "зажиг", "убер", "найди", "выйди",
  "стоп", "хватит", "громче", "тише",
  "заведи", "разбуди", "повтор", "пауз", "следующ", "предыдущ",
];

const normalizeWord = (word: string): string => word.toLowerCase().replaceAll("ё", "е");

/** Why a query is refused, or null when it may be sent. */
export function musicQueryProblem(query: unknown): string | null {
  if (typeof query !== "string") return "it must be a string";
  if (query.length === 0) return "it is empty";
  // Counted before anything else looks at the text, so a huge value is cheap to refuse.
  if (query.length > MAX_MUSIC_QUERY_LENGTH * 2 || Array.from(query).length > MAX_MUSIC_QUERY_LENGTH) {
    return `it is longer than ${MAX_MUSIC_QUERY_LENGTH} characters`;
  }
  if (!ALLOWED_QUERY.test(query) || query !== query.normalize("NFKC")) {
    return "it may hold only Latin and Russian letters in composed form, the digits 0-9, single spaces and the marks ' & -";
  }
  if (query.startsWith(" ") || query.endsWith(" ") || query.includes("  ")) {
    return "it must not start or end with a space or hold two spaces in a row";
  }
  if (!HAS_WORD.test(query)) return "it holds no letter or digit";
  const words = query.split(/[ '&-]+/u).filter((w) => w !== "").map(normalizeWord);
  if (words.length > MAX_MUSIC_QUERY_WORDS) return `it holds more than ${MAX_MUSIC_QUERY_WORDS} words`;
  for (const word of words) {
    if (HAS_LATIN.test(word) && HAS_CYRILLIC.test(word)) return "a word mixes Latin and Cyrillic letters";
    if (WAKE_WORDS.has(word)) return "it names the assistant; give only what to play";
    if (COMMAND_STEMS.some((stem) => word.startsWith(stem))) {
      return "it holds a command word; give only an artist, a track, an album, a genre or a mood";
    }
  }
  return null;
}

/** The spoken command for a query that musicQueryProblem accepted. */
export function playMusicCommand(query: string): string {
  const problem = musicQueryProblem(query);
  if (problem) throw new Error(`music query refused: ${problem}`);
  return PLAY_MUSIC_PREFIX + query;
}
