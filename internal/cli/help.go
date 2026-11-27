package cli

import (
	"fmt"
	"strings"
)

func synopsis(c *command) string {
	s := c.name()
	if c.Args != "" {
		s += " " + c.Args
	}
	return s + " [--flags]"
}

func flagLabel(f flagSpec) string {
	s := "--" + f.Long
	if f.Short != 0 {
		s = fmt.Sprintf("-%c, %s", f.Short, s)
	}
	if f.Long == "k" {
		s = "-K"
	}
	if f.Arg != "" {
		s += " <" + f.Arg + ">"
	}
	return s
}

// table renders rows as aligned plain text with two-space gutters.
func table(indent string, rows [][2]string) string {
	w := 0
	for _, r := range rows {
		if n := len([]rune(r[0])); n > w {
			w = n
		}
	}
	var b strings.Builder
	for _, r := range rows {
		pad := w - len([]rune(r[0]))
		fmt.Fprintf(&b, "%s%s%s  %s\n", indent, r[0], strings.Repeat(" ", pad), r[1])
	}
	return b.String()
}

func commandRows(filter func(*command) bool) [][2]string {
	var rows [][2]string
	for _, c := range commands {
		if filter(c) {
			label := c.name()
			if c.Args != "" {
				label += " " + c.Args
			}
			rows = append(rows, [2]string{label, c.Summary})
		}
	}
	return rows
}

func flagRows(fs []flagSpec) [][2]string {
	rows := make([][2]string, len(fs))
	for i, f := range fs {
		rows[i] = [2]string{flagLabel(f), f.Help}
	}
	return rows
}

const exitLine = "exit codes: 0 ok, 1 error, 2 usage, 3 pending\n"

// helpTop lists one row per noun (with its verbs) and one per top-level verb,
// all read from the command table, so it stays within 24 lines.
func helpTop() string {
	var rows [][2]string
	seen := map[string]bool{}
	for _, c := range commands {
		if seen[c.Path[0]] {
			continue
		}
		seen[c.Path[0]] = true
		if len(c.Path) == 1 {
			rows = append(rows, [2]string{c.Path[0], c.Summary})
			continue
		}
		var verbs []string
		for _, v := range commands {
			if len(v.Path) == 2 && v.Path[0] == c.Path[0] {
				verbs = append(verbs, v.Path[1])
			}
		}
		rows = append(rows, [2]string{c.Path[0] + " <verb>", strings.Join(verbs, ", ")})
	}
	var b strings.Builder
	b.WriteString("usage: chimera <noun> <verb> [args] [--flags]\n")
	b.WriteString("       chimera <verb> [args] [--flags]\n\n")
	b.WriteString("commands:\n")
	b.WriteString(table("  ", rows))
	b.WriteString("\nglobal flags:\n")
	b.WriteString(table("  ", flagRows(globals)))
	b.WriteString("\n" + exitLine)
	return b.String()
}

func helpGroup(group []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: chimera %s <verb> [args] [--flags]\n\n", group[0])
	b.WriteString("verbs:\n")
	b.WriteString(table("  ", commandRows(func(c *command) bool { return len(c.Path) == 2 && c.Path[0] == group[0] })))
	fmt.Fprintf(&b, "\nrun 'chimera %s <verb> --help' for flags\n", group[0])
	return b.String()
}

func helpCommand(c *command) string {
	var b strings.Builder
	fmt.Fprintf(&b, "usage: chimera %s\n\n%s\n", synopsis(c), c.Summary)
	if len(c.Detail) > 0 {
		b.WriteString("\n")
		for _, d := range c.Detail {
			b.WriteString(d + "\n")
		}
	}
	b.WriteString("\nflags:\n")
	b.WriteString(table("  ", flagRows(append(append([]flagSpec{}, c.Flags...), globals...))))
	b.WriteString("\n" + exitLine)
	return b.String()
}
