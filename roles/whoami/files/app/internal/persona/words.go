package persona

// 128 adjectives (7 bits), 64 colours (6 bits) and 64 animals (6 bits): about
// half a million distinct names before the code and rosette are counted.

var adjectives = [128]string{
	"Agile", "Ancient", "Arctic", "Astral", "Atomic", "Bold", "Brave", "Breezy",
	"Bright", "Brisk", "Bubbly", "Calm", "Candid", "Cheeky", "Chilly", "Clever",
	"Cosmic", "Cozy", "Crafty", "Crisp", "Curious", "Dapper", "Daring", "Dizzy",
	"Dreamy", "Dusky", "Eager", "Electric", "Elegant", "Epic", "Fancy", "Fearless",
	"Feisty", "Fiery", "Flashy", "Fluffy", "Frank", "Frosty", "Funky", "Fuzzy",
	"Gentle", "Giddy", "Glad", "Gleeful", "Graceful", "Grand", "Grumpy", "Happy",
	"Hasty", "Hearty", "Hidden", "Honest", "Humble", "Hungry", "Icy", "Jazzy",
	"Jolly", "Jovial", "Jumpy", "Keen", "Kind", "Lanky", "Lazy", "Lively",
	"Loyal", "Lucky", "Lunar", "Mellow", "Merry", "Mighty", "Misty", "Modest",
	"Mystic", "Neat", "Nifty", "Nimble", "Noble", "Odd", "Peppy", "Perky",
	"Plucky", "Polar", "Polite", "Proud", "Quick", "Quiet", "Quirky", "Rapid",
	"Restless", "Rowdy", "Royal", "Rustic", "Sassy", "Savvy", "Scrappy", "Shiny",
	"Shy", "Silent", "Sleepy", "Sly", "Snappy", "Sneaky", "Snowy", "Solar",
	"Sonic", "Speedy", "Spicy", "Spry", "Stealthy", "Steady", "Stellar", "Stoic",
	"Stormy", "Sturdy", "Subtle", "Sunny", "Swift", "Tender", "Thrifty", "Tidy",
	"Tiny", "Tranquil", "Velvet", "Vivid", "Wandering", "Wild", "Wise", "Witty",
}

type color struct{ name, hex string }

var colors = [64]color{
	{"Crimson", "#c8102e"}, {"Scarlet", "#e0301e"}, {"Ruby", "#9b111e"}, {"Cherry", "#d2042d"},
	{"Raspberry", "#d0105a"}, {"Rose", "#e0457b"}, {"Coral", "#f0643f"}, {"Salmon", "#ee8566"},
	{"Tangerine", "#f28500"}, {"Apricot", "#ef9a4a"}, {"Amber", "#f2a900"}, {"Saffron", "#e8b923"},
	{"Mustard", "#d4a017"}, {"Lemon", "#d9c400"}, {"Olive", "#7a7f1e"}, {"Lime", "#6bb82d"},
	{"Chartreuse", "#8ab800"}, {"Moss", "#6b8e23"}, {"Fern", "#4f7942"}, {"Sage", "#7d9a6b"},
	{"Emerald", "#1f9d55"}, {"Jade", "#00a86b"}, {"Mint", "#3eb489"}, {"Forest", "#228b22"},
	{"Pine", "#01796f"}, {"Teal", "#008080"}, {"Turquoise", "#1fbfb0"}, {"Aqua", "#00b5c8"},
	{"Cyan", "#00a3cc"}, {"Cerulean", "#007ba7"}, {"Azure", "#1e7fe0"}, {"Cobalt", "#0047ab"},
	{"Sapphire", "#0f52ba"}, {"Navy", "#253e8f"}, {"Indigo", "#4b2c91"}, {"Ultramarine", "#3b2fb5"},
	{"Periwinkle", "#7d86e0"}, {"Lavender", "#9b84d6"}, {"Violet", "#7f3fbf"}, {"Amethyst", "#9966cc"},
	{"Plum", "#8e4585"}, {"Orchid", "#c25fc0"}, {"Magenta", "#cc2299"}, {"Fuchsia", "#e0218a"},
	{"Mauve", "#a8749a"}, {"Maroon", "#7a1f2b"}, {"Burgundy", "#800020"}, {"Mahogany", "#c04000"},
	{"Rust", "#b7410e"}, {"Copper", "#b87333"}, {"Bronze", "#a97142"}, {"Ochre", "#cc7722"},
	{"Sienna", "#a0522d"}, {"Umber", "#6e4b2a"}, {"Cocoa", "#6f4e37"}, {"Caramel", "#b8781a"},
	{"Tan", "#b9905e"}, {"Sand", "#c9a86a"}, {"Khaki", "#a89f5b"}, {"Slate", "#5a6b7c"},
	{"Steel", "#4682b4"}, {"Graphite", "#4b4f54"}, {"Pewter", "#7f8a8e"}, {"Silver", "#9aa3b0"},
}

type animal struct{ name, emoji string }

// Every emoji here is from Unicode 12 or earlier, so it renders on any
// system from the last several years.
var animals = [64]animal{
	{"Fox", "🦊"}, {"Octopus", "🐙"}, {"Turtle", "🐢"}, {"Owl", "🦉"},
	{"Bee", "🐝"}, {"Butterfly", "🦋"}, {"Dolphin", "🐬"}, {"Penguin", "🐧"},
	{"Lion", "🦁"}, {"Tiger", "🐯"}, {"Panda", "🐼"}, {"Koala", "🐨"},
	{"Frog", "🐸"}, {"Unicorn", "🦄"}, {"Whale", "🐳"}, {"Crab", "🦀"},
	{"Hedgehog", "🦔"}, {"Giraffe", "🦒"}, {"Zebra", "🦓"}, {"Kangaroo", "🦘"},
	{"Llama", "🦙"}, {"Hippo", "🦛"}, {"Parrot", "🦜"}, {"Peacock", "🦚"},
	{"Swan", "🦢"}, {"Raccoon", "🦝"}, {"Badger", "🦡"}, {"Lobster", "🦞"},
	{"Otter", "🦦"}, {"Sloth", "🦥"}, {"Flamingo", "🦩"}, {"Skunk", "🦨"},
	{"Bat", "🦇"}, {"Wolf", "🐺"}, {"Boar", "🐗"}, {"Horse", "🐴"},
	{"Cow", "🐮"}, {"Pig", "🐷"}, {"Mouse", "🐭"}, {"Hamster", "🐹"},
	{"Rabbit", "🐰"}, {"Bear", "🐻"}, {"Chick", "🐥"}, {"Duck", "🦆"},
	{"Eagle", "🦅"}, {"Snail", "🐌"}, {"Ladybug", "🐞"}, {"Cat", "🐱"},
	{"Lizard", "🦎"}, {"Rex", "🦖"}, {"Dragon", "🐲"}, {"Crocodile", "🐊"},
	{"Fish", "🐠"}, {"Puffer", "🐡"}, {"Shark", "🦈"}, {"Shrimp", "🦐"},
	{"Squid", "🦑"}, {"Camel", "🐫"}, {"Rhino", "🦏"}, {"Elephant", "🐘"},
	{"Gorilla", "🦍"}, {"Monkey", "🐒"}, {"Goat", "🐐"}, {"Deer", "🦌"},
}
