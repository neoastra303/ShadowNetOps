# Cybersecurity Red Team Terminal - Design Guidelines

## Design Approach
**Reference-Based: Cyberpunk + Spy-Tech Fusion**
Drawing inspiration from cyberpunk aesthetics (Blade Runner, Cyberpunk 2077 UI) combined with modern terminal interfaces (Warp, Hyper) and tactical dashboards (military command centers, CIA operations rooms).

## Core Design Principles
1. **High-Contrast Minimalism**: Clean, purposeful interfaces with dramatic neon accents
2. **Terminal-First**: Monospaced typography and command-line inspired interactions
3. **Tactical Precision**: Every element serves a functional purpose
4. **Cyberpunk Atmosphere**: Subtle glitch effects and neon glow treatments

## Color Palette

**Dark Mode (Primary)**
- Background Base: 220 20% 8% (deep charcoal-blue)
- Background Elevated: 220 18% 12% (slightly lighter panels)
- Background Terminal: 220 25% 6% (deeper for terminal areas)

**Neon Accents**
- Primary Cyan: 180 100% 50% (electric cyan for primary actions, active states)
- Secondary Magenta: 320 100% 60% (magenta for alerts, critical items)
- Success Green: 140 90% 50% (matrix-green for successful operations)
- Warning Amber: 40 100% 60% (amber for warnings)
- Error Red: 0 85% 60% (red for errors, vulnerabilities)

**Text**
- Primary Text: 180 20% 95% (slightly cyan-tinted white)
- Secondary Text: 180 15% 65% (muted cyan-gray)
- Terminal Text: 140 80% 65% (soft matrix green)

## Typography

**Font Families**
- Primary/Terminal: 'JetBrains Mono', 'Fira Code', monospace (via Google Fonts)
- UI Headers: 'Inter', sans-serif (minimal use for section titles)

**Scale**
- Terminal Text: text-sm (14px) - primary command/output
- UI Labels: text-xs (12px) - metadata, timestamps
- Section Headers: text-lg font-semibold (18px)
- Metric Values: text-3xl font-bold (30px) - key statistics

## Layout System

**Spacing Units**: Tailwind units of 2, 4, 6, 8 for consistent rhythm
- Component padding: p-4 to p-6
- Section gaps: gap-6 to gap-8
- Terminal line height: leading-relaxed

**Grid Structure**
- Sidebar: w-64 (navigation, tool selector)
- Main Terminal: flex-1 (primary workspace)
- Status Panel: w-80 (metrics, live updates)
- Use CSS Grid for dashboard sections: grid-cols-1 lg:grid-cols-3

## Component Library

**Terminal Windows**
- Border: border border-cyan-500/30 with shadow-lg shadow-cyan-500/10
- Background: bg-[#0a0e15] (darkest)
- Cursor: Animated blinking block in cyan
- Prompt: Cyan username/path with magenta symbols

**Cards/Panels**
- Glass morphism effect: bg-slate-900/50 backdrop-blur-sm
- Subtle borders: border border-cyan-500/20
- Hover state: border-cyan-500/50 with glow effect

**Buttons**
- Primary: bg-cyan-500 text-black font-semibold with hover glow
- Secondary: border border-cyan-500 text-cyan-500 with hover:bg-cyan-500/10
- Danger: border border-red-500 text-red-500

**Data Visualization**
- Vulnerability bars: Horizontal bars with neon gradient fills
- Port status: Grid of small indicators (green=open, red=closed, amber=filtered)
- Network graphs: SVG with neon stroke lines
- Metrics: Large numbers with small sparkline charts

**Navigation**
- Vertical sidebar with icon + label
- Active state: bg-cyan-500/20 border-l-4 border-cyan-500
- Icons: Heroicons (outline style) in cyan-500

**Forms**
- Input fields: bg-slate-900 border border-cyan-500/30 focus:border-cyan-500
- Labels: text-xs text-cyan-400 uppercase tracking-wide
- Checkboxes/Radio: Custom styled with cyan accents

**Special Effects**
- Scanline overlay: Subtle horizontal lines with low opacity animation
- Glitch effect: Occasional text shift/RGB split on headers (very subtle, <1s duration)
- Glow: box-shadow with cyan/magenta blur on active elements
- Loading states: Animated progress bars with neon gradient

## Key Screens/Sections

**Dashboard Overview**
- 3-column metric cards (active scans, vulnerabilities found, tools running)
- Live terminal output stream
- Network topology visualization
- Recent findings table

**Recon Module**
- IP/Domain input with autocomplete
- Port scan progress indicator
- Results in terminal-style list with color-coded status
- Export options panel

**Vulnerability Assessment**
- CVE database search
- Risk matrix visualization (heat map)
- Detailed finding cards with severity badges
- Report generation interface

**OSINT Tools**
- Multi-tab interface for different sources
- Data correlation graph
- Timeline visualization
- Entity relationship mapper

**Password Testing**
- Strength meter with rainbow gradient (weak=red to strong=green)
- Character set indicators
- Breach database check status
- Dictionary attack simulation

## Interactions
- Command autocomplete in terminal (Tab key)
- Typewriter effect for system messages
- Smooth scroll in terminal output
- Click to copy IP addresses, hashes, commands
- Hover tooltips for technical terms

## No Images Required
This is a functional application interface - no hero images or decorative photography needed. All visuals are data-driven UI elements, charts, and terminal outputs.