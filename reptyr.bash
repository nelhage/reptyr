# bash completion for reptyr(1)

_reptyr()
{
    case $3 in
        -l|-L|-h|-v) return ;;
    esac

    if [[ $2 == -* ]]; then
        COMPREPLY=( $(compgen -W '-l -L -s -T -h -v -V' -- "$2") )
        return
    fi

    case $3 in
        [1-9]*) ;;
        *) COMPREPLY=( $(compgen -W '$(command ps axo pid=)' -- "$2") ) ;;
    esac
} &&
complete -F _reptyr reptyr
