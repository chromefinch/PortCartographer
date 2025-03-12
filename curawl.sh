#!/bin/bash
print_purple (){
    echo -ne "\033[0;35m$1\033[0m"
}

print_purple "Hi! I'm painfully slow garbage!"
echo ""
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
hakrawler_file="hakrawler_$domain.txt"
echo "$1" > "$visited_file"

# Initial scrape of links
curl -s "$1" | grep -Eo '=\"\/[.a-z,A-Z\/-]{1,}\"|https?://[^"]+' | sed "s|=\"|$1|g" | sed "s|\"||g" | sort -u > "$seen_file" 2>/dev/null
stop=$(wc -l "$seen_file" | awk '{print $1}')
start=0
print_purple "Starting with $stop links found."
echo ""

while [[ $start -ne $stop ]]; do
  start=$stop
  for i in $(cat "$seen_file"); do
    if grep -qFx "$i" "$visited_file" 2>/dev/null; then
      echo "Duplicate: $i" >/dev/null 2>&1; 
    else
      # Check if the link matches the domain
      if [[ "$i" == *"$domain"* ]]; then
        #echo "Crawling: $i"
        # Crawl only domain-matching links
        curl -A "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/81.0" -s "$i" | grep -Eo '=\"\/[#.a-z,A-Z\/-]{1,}\"|https?://[^"]+|href=\"/[^\"]*\\'  | sed "s|href=\"|$1|g" | sed "s|=\"|$1|g" | sed "s|\"||g" | grep -E 'https?://+' >> "$seen_file" 2>/dev/null
        echo "$i" | grep -E 'https?://+' >> "$visited_file" 2>/dev/null
      else
        # Add non-domain links to seen_file only
        #echo "Adding non-domain link to seen file: $i"
        echo "$i" | grep -E 'https?://+' >> "$visited_file" 2>/dev/null
      fi
    fi
  
  sort -u "$seen_file" -o "$seen_file"
  stop=$(wc -l "$seen_file" | awk '{print $1}')
  print_purple "Progress: $stop links visited.\r"
  done

  sort -u "$visited_file" -o "$visited_file"
  stop=$(wc -l "$seen_file" | awk '{print $1}')
  #print_purple "Progress: $stop links visited."
done
echo ""
total=$(wc -l "$visited_file" | awk '{print $1}')

for i in $(cat "$visited_file"); do
  if [[ "$i" == *"$domain"* ]]; then
    # Crawl only domain-matching links
    echo "$i" | hakrawler -u -d 0 -insecure -timeout 5 -t 20 >> "$hakrawler_file"  2>/dev/null
  fi
    c=$(($c + 1))
    percent=$(($c * 100 / $total))
    bar_length=$((percent * 20 / 100))
    bar=""
    for j in $(seq 1 $bar_length); do
      bar+="="
    done
    spaces=""
    for k in $(seq 1 $((20 - bar_length))); do
      spaces+=" "
    done
    echo -ne "Hakrawler Progress: [$bar$spaces] $percent%\r"
done
sort -u "$hakrawler_file" -o "$hakrawler_file"
print_purple "Finished! Total links visited: $total "
echo See files "$hakrawler_file" and "$visited_file" 
# Cleanup
rm -r "$tmp_dir"
