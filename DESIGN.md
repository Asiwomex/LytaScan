# LytaScan design

LytaScan helps an AWS operator find the affected resource, understand the evidence, and decide what to do next. Public pages explain the workflow through a saved scan. The organization workspace exposes the real controls implemented in the application.

## Homepage

- A light, sticky header links to Demo, How it works, Checks, and Status. At narrow widths those links move into the menu. Show sign-in or the organization destination when the configured environment supports it.
- The hero leads with the AWS review workflow. Its console has an Inventory, Evaluate, Prioritize, and Verify rail, a results table, and a navy evidence panel. Selecting a row updates the evidence. **Run walkthrough** replays fictional scan data and can be stopped or stepped through manually.
- On phones, the stage rail becomes a row of controls and the evidence stacks below the results. The heading is kept compact so the console can start higher on short screens.
- The embedded demo prioritizes the scan summary and findings. **Scan breakdown** opens the pillar wall and breakdown filters. Findings are shown eight rows at a time. Search, account changes, filters, and sorting return to the first page.
- Below the demo, keep the workflow, CLI example, six-pillar check table, project status, and footer compact. The table keeps its column headings and wraps text at small widths. Its disclosure lists the full catalog. The footer carries the demo link, credits, source, and Back to top.

## Standalone demo and workspace

| Surface | Design and behavior |
| --- | --- |
| **Demo** | At wide widths the left rail links to Overview, Findings, and the site. On phones the rail becomes a top navigation. An explicit sample-data label distinguishes the demo from the workspace. Theme can follow the device or be set to light or dark. Reset demo restores the report's default chart and filters. |
| **Scan report** | Show posture and trend first. Select Posture score or Failed checks to switch the plotted metric. Each pillar block represents an evaluation. Selecting a block or a finding row opens details and remediation. Breakdown rows act as filters, and filter chips explain what is applied. |
| **Organizations** | Use the same blue-accented shell for the organization picker, scan jobs, tracked findings, connections, and team. Navigation follows the user's role. On smaller screens the menu and job rows reflow so actions and state labels remain visible. |
| **Scan progress** | Show how many rule scopes have settled, then list the rule, region, state, evaluation totals, and timing. Keep incomplete reasons visible. Authorized users can retry a retryable scope from a finished job. |
| **Tracked findings** | Technical evaluation and workflow status are separate. Show the affected resource, remediation, user comments, and timeline in the detail view. Keep the recorded reason visible when inventory confirms a resource was deleted. |
| **Authentication and connection setup** | Keep email verification and role setup ordered. Label local preview and simulated verification wherever relevant. Give users a next step when a screen requires a different role or an active organization. |

## Visual system

The shared UI uses white surfaces, blue-gray borders, slate text, and a blue brand accent. The hero adds a faint blue grid behind the console. Navy is used for evidence, terminal instructions, and the footer.

| Token | Light value | Role |
| --- | --- | --- |
| Page | `#F5F7FA` | App background |
| Surface | `#FFFFFF` | Panels, tables, and sheets |
| Ink | `#0F1B2D` | Primary text |
| Muted ink | `#5B6B80` | Secondary text |
| Line | `#DFE4EC` | Table and panel borders |
| Sound / brand | `#175CD3` | Passes, links, and focus on light surfaces |
| Sound tint | `#EDF4FF` | Selected and highlighted surfaces |
| Homepage navy and pale blue | `#0B172B` / `#A9CBFF` | Dark fields and accents on navy |

Instrument Sans is the preferred UI face with system fallbacks. Monospace is reserved for commands and machine identifiers. Severity colors are paired with a text label or an accessible name. Charts use a line with a fitted axis and an accessible text summary. Use real links, buttons, tables, and disclosures with visible keyboard focus. Motion is brief and honors reduced-motion preferences.

The CSS variables live in [globals.css](web/app/globals.css). The [homepage hero](web/components/site/home-hero.module.css), [homepage sections](web/components/site/home-sections.module.css), and [workspace shell](web/components/account/workspace-shell.module.css) define their local layouts.
