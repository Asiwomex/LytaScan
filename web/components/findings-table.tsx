"use client";

import { useMemo, useState } from "react";
import {
  createColumnHelper,
  createSortedRowModel,
  rowSortingFeature,
  tableFeatures,
  useTable,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronLeft, ChevronRight, ChevronsUpDown } from "lucide-react";

import { SeverityMark, StatusMark } from "@/components/severity-mark";
import {
  SEVERITIES,
  STATUSES,
  resourceName,
  serviceOf,
  type FindingGroup,
} from "@/lib/findings";
import { cn } from "@/lib/utils";

const features = tableFeatures({
  rowSortingFeature,
  sortedRowModel: createSortedRowModel(),
});

const helper = createColumnHelper<typeof features, FindingGroup>();

function compare(a: string | number, b: string | number): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// Columns that drop out on narrow screens; the detail panel still has them.
const COLUMN_CLASS: Record<string, string> = {
  severity: "w-[5.5rem] sm:w-28",
  service: "hidden w-36 md:table-cell",
  region: "hidden w-40 lg:table-cell",
  status: "w-20 sm:w-32",
};

function regionLabel(group: FindingGroup): string {
  return group.regions.length > 1 ? `${group.regions.length} regions` : group.regions[0];
}

function buildColumns(onSelect: (group: FindingGroup) => void) {
  return helper.columns([
    // Severity and status sort by rank, not alphabetically.
    helper.accessor((group) => SEVERITIES.indexOf(group.finding.severity), {
      id: "severity",
      header: "Severity",
      sortFn: (a, b, id) => compare(a.getValue<number>(id), b.getValue<number>(id)),
      cell: ({ row }) => <SeverityMark severity={row.original.finding.severity} />,
    }),
    helper.accessor((group) => group.finding.title, {
      id: "title",
      header: "Finding",
      sortFn: (a, b, id) => compare(a.getValue<string>(id), b.getValue<string>(id)),
      cell: ({ row }) => (
        <>
          <button
            type="button"
            onClick={(event) => {
              event.stopPropagation();
              onSelect(row.original);
            }}
            className="text-left font-medium underline-offset-4 group-hover:underline"
          >
            {row.original.finding.title}
          </button>
          <code className="mt-0.5 block font-mono text-xs break-all text-muted-ink">
            {resourceName(row.original.finding.resource_arn)}
          </code>
        </>
      ),
    }),
    helper.accessor((group) => serviceOf(group.finding), {
      id: "service",
      header: "Service",
      sortFn: (a, b, id) => compare(a.getValue<string>(id), b.getValue<string>(id)),
    }),
    helper.accessor((group) => regionLabel(group), {
      id: "region",
      header: "Region",
      sortFn: (a, b, id) => compare(a.getValue<string>(id), b.getValue<string>(id)),
      cell: ({ row }) =>
        row.original.regions.length > 1 ? (
          // The same setting, found in several regions, is one row.
          <span className="whitespace-nowrap">{regionLabel(row.original)}</span>
        ) : (
          <code className="font-mono text-xs whitespace-nowrap">{regionLabel(row.original)}</code>
        ),
    }),
    helper.accessor((group) => STATUSES.indexOf(group.finding.status), {
      id: "status",
      header: "Status",
      sortFn: (a, b, id) => compare(a.getValue<number>(id), b.getValue<number>(id)),
      cell: ({ row }) => <StatusMark status={row.original.finding.status} />,
    }),
  ]);
}

export function FindingsTable({
  groups,
  onSelect,
  pagination,
}: {
  groups: FindingGroup[];
  onSelect: (group: FindingGroup) => void;
  pagination?: { page: number; size: number; onPageChange: (page: number) => void };
}) {
  const [sorting, setSorting] = useState<SortingState>([{ id: "severity", desc: false }]);
  const columns = useMemo(() => buildColumns(onSelect), [onSelect]);
  const table = useTable({
    features,
    columns,
    data: groups,
    state: { sorting },
    onSortingChange: (nextSorting) => {
      setSorting(nextSorting);
      pagination?.onPageChange(0);
    },
  });

  const rows = table.getRowModel().rows;
  const pageStart = pagination ? pagination.page * pagination.size : 0;
  const pageEnd = pagination ? Math.min(pageStart + pagination.size, rows.length) : rows.length;
  const compact = Boolean(pagination);

  return (
    <>
      <table className={cn("w-full border-collapse text-[0.8125rem]", compact && "max-sm:table-fixed")}>
        <thead>
          {table.getHeaderGroups().map((group) => (
            <tr key={group.id} className="border-y border-line bg-page">
              {group.headers.map((header) => {
                const sorted = header.column.getIsSorted();
                const SortIcon =
                  sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ChevronsUpDown;
                return (
                  <th
                    key={header.id}
                    scope="col"
                    aria-sort={
                      sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none"
                    }
                    className={cn("text-left font-medium", COLUMN_CLASS[header.column.id], compact ? "px-2 py-2 md:px-3" : "px-3 py-2 sm:px-5", compact && header.column.id === "severity" && "max-sm:w-[4.5rem]", compact && header.column.id === "status" && "max-sm:w-[4.1rem]")}
                  >
                    <button
                      type="button"
                      onClick={header.column.getToggleSortingHandler()}
                      className={cn(
                        "inline-flex items-center gap-1 text-muted-ink hover:text-ink",
                        sorted && "text-ink",
                        compact && "max-sm:min-h-7 max-sm:gap-0.5",
                      )}
                    >
                      <table.FlexRender header={header} />
                      <SortIcon className={cn("size-3.5 shrink-0", !sorted && "opacity-50", compact && "max-sm:size-2.5")} aria-hidden="true" />
                    </button>
                  </th>
                );
              })}
            </tr>
          ))}
        </thead>
        <tbody>
          {rows.slice(pageStart, pageEnd).map((row) => (
            <tr
              key={row.id}
              onClick={() => onSelect(row.original)}
              className="group cursor-pointer border-b border-line align-top transition-colors duration-150 last:border-b-0 hover:bg-page"
            >
              {row.getAllCells().map((cell) => (
                <td key={cell.id} className={cn(COLUMN_CLASS[cell.column.id], compact ? "px-2 py-2 md:px-3" : "px-3 py-3 sm:px-5", compact && cell.column.id === "title" && "wrap-anywhere", compact && "max-sm:[&_span]:whitespace-normal max-sm:[&_svg]:shrink-0")}>
                  <table.FlexRender cell={cell} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {pagination && rows.length > pagination.size && (
        <nav aria-label="Findings pages" className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1 border-t border-line px-2.5 py-1.5 text-xs text-muted-ink sm:px-3">
          <span role="status">{pageStart + 1}–{pageEnd} of {rows.length} rows</span>
          <div className="flex gap-1">
            <button type="button" disabled={pageStart === 0} onClick={() => pagination.onPageChange(pagination.page - 1)}
              className="inline-flex min-h-9 items-center gap-0.5 rounded border border-line px-1.5 font-medium text-ink enabled:hover:bg-page disabled:opacity-50">
              <ChevronLeft size={14} aria-hidden="true" /> Previous
            </button>
            <button type="button" disabled={pageEnd === rows.length} onClick={() => pagination.onPageChange(pagination.page + 1)}
              className="inline-flex min-h-9 items-center gap-0.5 rounded border border-line px-1.5 font-medium text-ink enabled:hover:bg-page disabled:opacity-50">
              Next <ChevronRight size={14} aria-hidden="true" />
            </button>
          </div>
        </nav>
      )}
    </>
  );
}
