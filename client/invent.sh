#!/bin/bash

# Source env vars
source /etc/default/invent-client

datadir="${INVENT_DIR}/data"
export_endpoint="${INVENT_EXPORT_ENDPOINT}"
fact_dir="/var/lib/puppet/facts.d"
filename="${datadir}/data-$(date +%Y%m%dT%H%M%S).json"
host_os="${INVENT_HOST_OS}"
latest="${datadir}/latest.json"
retention_days="${INVENT_RETENTION_DAYS}"

# Gather packages
parse_command="awk -v q='\"' '{print \"{\"q\"name\"q\": \"q\$1q\",\"q\"version\"q\": \"q\$2q\"}\"}' | jq -s ."

case "${host_os}" in
  alpine)
    query_command="apk list -q"
    parse_command="awk '{print \$1}' | sed 's/\-\\([0-9]\\)/ \1/' | ${parse_command}"
    ;;
  centos | fedora | redhat)
    query_command="rpm -qa"
    parse_command="sed 's/\-\\([0-9]\\)/ \1/' |${parse_command}"
    ;;
  debian | ubuntu)
    query_command="dpkg-query -W"
    ;;
  *)
    query_command='echo {\"unknown\": \"none\"}'
    parse_command='cat -'
esac

# Gather structured data kernel fact
kernel_fact="${fact_dir}/kernel.json"
uname -rvmo | sed -e 's/ #/;#/' -e 's/ \([^ ]\+\) \([^ ]\+\)$/;\1;\2/'| \
  awk -F ';' '{print "{ \"running-kernel\": { \"kernel-release\": \""$1"\",\"kernel-version\": \""$2"\", \"machine\": \""$3"\", \"operating-system\": \""$4"\" }}"}' | \
  jq . > ${kernel_fact}
# Gather structured data package fact
package_fact="${fact_dir}/packages.json"
echo "{
        \"packages\": $(eval ${query_command} | eval ${parse_command} 2> /dev/null | jq -s .)
      }" \
    | jq . > ${package_fact}

# Only run if we have docker
if [ $(which docker) ]; then
  # Gather structured data docker fact
  docker_fact="${fact_dir}/docker_ps.json"
  for container in $(docker ps -q); do
    docker ps  --format '{{json . }}' --filter "id=${container}" | jq '. |= . + '{"ImageId":$(docker inspect --format '{{json .Image }}' ${container})'}';
  done | jq -s |jq -s  '{docker_ps: add}' > ${docker_fact}

fi

# Export facts
mkdir -p ${datadir}
puppet facts --render-as json 2>/dev/null | jq . > ${filename}
ln -f -s "${filename}" "${latest}"

# Clean out old facts
find ${datadir} -type f -mtime +${retention_days} -delete

# Send data to inventory receiver
if [[ -x /usr/bin/curl ]] && [[ -n ${export_endpoint} ]]; then
  username=$(hostname -f)
  pwfile="/opt/invent/passwd"
  if [[ -f ${pwfile} ]]; then
    password=$(cat ${pwfile})
  else
    mkdir -p $(basename ${pwfile})
    password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 256 | head -n 1)
    echo ${password} > ${pwfile}
  fi
  curl -X POST -H 'accept: application/json' \
    -F "file=@${filename}" \
    --user ${username}:${password}  \
    ${export_endpoint}/host/${username}
fi
