#!/bin/bash
print_purple (){
    echo -e "\033[0;35m$1\033[0m"
}

print_purple "Hi! I'm painfully slow garbage!"
if [[ -z "$1" ]]; then
  echo "Usage: $0 <URL>"
  exit 1
fi

domain=$(echo "$1" | awk -F/ '{print $3}')
if [[ -z "$domain" ]]; then
  echo "Invalid URL. Please provide a valid one."
  exit 1
fi

echo "Crawling domain: $domain"
tmp_dir=$(mktemp -d)
seen_file="$tmp_dir/seen_$domain.txt"
visited_file="crawled_$domain.txt"
echo "$1" > "$visited_file"

# Initial scrape of links
curl -s "$1" | grep -Eo '=\"\/[.a-z,A-Z\/-]{1,}\"|https?://[^"]+' | sed "s|=\"|$1|g" | sed "s|\"||g" | sort -u > "$seen_file"
stop=$(wc -l "$seen_file" | awk '{print $1}')
start=0
print_purple "Starting with $stop links found."

while [[ $start -ne $stop ]]; do
  start=$stop
  for i in $(cat "$seen_file"); do
    if grep -qFx "$i" "$visited_file"; then
      echo "Duplicate: $i" >/dev/null 2>&1; 
    else
      # Check if the link matches the domain
      if [[ "$i" == *"$domain"* ]]; then
        echo "Crawling: $i"
        # Crawl only domain-matching links
        curl -A "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0" -s "$i" | grep -Eo '=\"\/[#.a-z,A-Z\/-]{1,}\"|https?://[^"]+|href=\"/[^\"]*\\' | sed "s|href=\"|$1|g" | sed "s|=\"|$1|g" | sed "s|\"||g" | grep -E 'https?://+' >> "$seen_file"
        echo "$i" | grep -E 'https?://+' >> "$visited_file"
      else
        # Add non-domain links to seen_file only
        echo "Adding non-domain link to seen file: $i"
        echo "$i" | grep -E 'https?://+' >> "$visited_file"
      fi
    fi
  done

  sort -u "$seen_file" -o "$seen_file"
  sort -u "$visited_file" -o "$visited_file"
  stop=$(wc -l "$seen_file" | awk '{print $1}')
  print_purple "Progress: $stop links visited."
done

total=$(wc -l "$visited_file" | awk '{print $1}')
cat "$visited_file"
print_purple "Finished! Total links visited: $total"

# Cleanup
rm -r "$tmp_dir"
